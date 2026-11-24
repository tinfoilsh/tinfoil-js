/**
 * The verification report: the steps that a verification ran, and the facts
 * that it established. The verifier returns one for a document that it
 * accepts, and a {@link VerificationError} carries one for a document that
 * it rejects, so that a caller can show what happened either way.
 */
import { CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, type CryptoMaterialItem } from "./document/document.js";
import { UsageError, type Layer } from "./errors.js";
import { fromHex, sha256, toHex } from "./internal/bytes.js";
import { cloneExpected, cloneMeasurement, type Expected, type Measurement } from "./measurement.js";
import {
  artifactJSON,
  configJSON,
  copyArtifact,
  copyConfig,
  copyVerifiedFacts,
  cryptoMaterialData,
  freezeDeep,
  measurementJSON,
  type ArtifactVerification,
  type ArtifactVerificationJSON,
  type ConfigVerification,
  type ConfigVerificationJSON,
  type MeasurementJSON,
  type VerificationMetadata,
  type VerificationMetadataJSON,
  type VerifiedFacts,
  type VerifiedFactsJSON,
} from "./verification.js";

/**
 * The outcome of a {@link Step}: `passed` when every check of its layer ran
 * and passed, `failed` when its layer rejected the document, `skipped` when
 * the layer had nothing to check, as for provenance when the verifier
 * embeds every reference value, and `not_run` when the step did not run in
 * full because another layer rejected the document first.
 */
export type StepStatus = "passed" | "failed" | "skipped" | "not_run";

/** The outcome of one verification layer. */
export interface Step {
  readonly layer: Layer;
  readonly status: StepStatus;
  /**
   * For a failed step, the message of the check that failed: the
   * {@link VerificationError}'s message without its `verification error:
   * <layer>: ` prefix, since the step already names its layer. For a skipped
   * step, the reason that it was skipped, and "" otherwise. It is
   * diagnostic: callers must not parse it.
   */
  readonly message: string;
}

/** What the CPU's authenticated quote proves. */
export interface CPUEvidence {
  /** Every register that the hardware measured, in its platform's native layout. */
  readonly measurement: Measurement;
}

/**
 * What the document and its hardware evidence claim. The policy step is the
 * only one that binds the channel keys to the enclave, so in a rejected
 * report the key fingerprints are always unverified: they are only what the
 * document claims, and must be shown as such.
 */
export interface MeasuredFacts {
  /** Set only once the quote step passed, so that what it holds came from the hardware. */
  readonly cpu?: CPUEvidence;
  /** The SHA-256 fingerprint of the TLS key's SPKI, lowercase hex, that the document endorses, if any. */
  readonly tlsPublicKeyFP?: string;
  /** The lowercase-hex SHA-256 of the HPKE public key's bytes that the document endorses, if any; never the key itself. */
  readonly hpkePublicKeyFP?: string;
}

/** The reference values that the provenance step accepted: what the enclave should be running. */
export interface ExpectedFacts {
  /** The selected code or runtime repository, without version pins. */
  readonly configRepo: string;
  /** The code release, or the runtime for a config-based verification. */
  readonly artifact: ArtifactVerification;
  /** The config that a config-based verification accepted; undefined for a code release. */
  readonly config?: ConfigVerification;
  /** The platform endorsements that a config-based verification accepted; undefined for a code release. */
  readonly platform?: ArtifactVerification;
  /**
   * The registers that the release fixes, in the layout of the platform that
   * the document's CPU evidence names; a register that the release leaves to
   * the platform is unset. Undefined if the release fixes nothing usable on
   * that platform. The values are authenticated; the platform that selects
   * their layout is authenticated only once the quote step passed.
   */
  readonly codeMeasurement?: Expected;
  /**
   * Every register that the quote must attest: the code measurement, the
   * verifier's pinned registers and the platform registers that the
   * endorsed platform supplies, such as TDX MRTD and RTMR0. Set once the
   * policy step resolved them, even if a later check of that step failed,
   * and undefined otherwise.
   */
  readonly measurement?: Measurement;
}

/**
 * What a rejected verification established before the step that failed.
 * Every value in them is authenticated, except the key fingerprints, which
 * {@link MeasuredFacts} describes, and the platform that selects the layout
 * of the code measurement before the quote step passed, which
 * {@link ExpectedFacts} describes.
 */
export interface PartialFacts {
  /** Undefined unless the provenance step passed or was skipped. */
  readonly expected?: ExpectedFacts;
  /** Undefined unless the envelope step passed. */
  readonly measured?: MeasuredFacts;
}

/** The JSON form of a {@link MeasuredFacts}. */
export interface MeasuredFactsJSON {
  readonly cpu?: { readonly measurement: MeasurementJSON };
  readonly tlsPublicKeyFP?: string;
  readonly hpkePublicKeyFP?: string;
}

/** The JSON form of an {@link ExpectedFacts}. */
export interface ExpectedFactsJSON {
  readonly configRepo: string;
  readonly artifact: ArtifactVerificationJSON;
  readonly config?: ConfigVerificationJSON;
  readonly platform?: ArtifactVerificationJSON;
  readonly codeMeasurement?: MeasurementJSON;
  readonly measurement?: MeasurementJSON;
}

/** The JSON form of a {@link PartialFacts}. */
export interface PartialFactsJSON {
  readonly expected?: ExpectedFactsJSON;
  readonly measured?: MeasuredFactsJSON;
}

/**
 * The JSON form of a {@link VerificationReport}, as `toJSON()` returns it
 * and `JSON.stringify` serializes it: the same fields as the properties,
 * with registers as lowercase hex and times as ISO 8601 strings. Facts that
 * were not established are left out.
 */
export interface VerificationReportJSON {
  readonly steps: readonly Step[];
  readonly verifiedFacts?: VerifiedFactsJSON;
  readonly partialFacts?: PartialFactsJSON;
  readonly metadata: VerificationMetadataJSON;
}

/** @internal What a report is built from; exactly one of the facts is set. */
interface ReportFields {
  readonly steps: readonly Step[];
  readonly verifiedFacts?: VerifiedFacts;
  readonly partialFacts?: PartialFacts;
  readonly metadata: VerificationMetadata;
}

/** Only this module holds the token that the constructor requires, so that untyped code that calls it is refused. */
const BUILT_HERE: unique symbol = Symbol("VerificationReport");

/** Calls the private constructor; the class assigns it, as the only place that the constructor can be called. */
let construct: (fields: ReportFields) => VerificationReport;

/**
 * One verification of an attestation document, step by step, and what the
 * steps established. `verifyV3` returns one for a document that it accepts,
 * whose `verifiedFacts` are set and none of whose steps failed; a
 * {@link VerificationError} carries one for a document that it rejects, in
 * which one step failed and `partialFacts` are set. A report authorizes
 * nothing: only the channel keys in `verifiedFacts` may be bound to.
 *
 * A report is plain data. It and everything nested in it are frozen, except
 * register bytes (`Uint8Array`) and `Date` values, which have no frozen form
 * in the language and must not be mutated; {@link clone} gives a copy that
 * shares neither. Only the verifier creates a report: the constructor is
 * private. Its data properties survive a structured clone, such as
 * `postMessage`, as a plain object, and `toJSON()` gives a serializable copy
 * for logging or persisting.
 */
export class VerificationReport {
  /**
   * One step for each layer, in layer order: today `envelope`, `provenance`,
   * `quote` and `policy`. A later version may add a layer, and with it a
   * step.
   */
  readonly steps: readonly Step[];
  /** Set if and only if no step failed. It is the only part of a report that carries the keys that a channel binds to. */
  readonly verifiedFacts?: VerifiedFacts;
  /** Set if and only if a step failed: what the steps before the failure established. */
  readonly partialFacts?: PartialFacts;
  /** The verifier's name and version, and the instant that the document was appraised at. The document does not attest them. */
  readonly metadata: VerificationMetadata;

  private constructor(token: typeof BUILT_HERE, fields: ReportFields) {
    if (token !== BUILT_HERE) throw new UsageError("a verification report comes from a verifier: verify a document to get one");
    if ((fields.verifiedFacts === undefined) === (fields.partialFacts === undefined)) {
      throw new UsageError("a verification report holds either verified facts or partial facts");
    }
    this.steps = freezeDeep(fields.steps.map((s) => ({ layer: s.layer, status: s.status, message: s.message })));
    if (fields.verifiedFacts !== undefined) this.verifiedFacts = fields.verifiedFacts;
    if (fields.partialFacts !== undefined) this.partialFacts = freezeDeep(copyPartial(fields.partialFacts));
    this.metadata = freezeDeep({ verifier: { ...fields.metadata.verifier }, verifiedAt: new Date(fields.metadata.verifiedAt.getTime()) });
    Object.freeze(this);
  }

  static {
    construct = (fields) => new VerificationReport(BUILT_HERE, fields);
  }

  /** The step that failed, or undefined when none did. */
  failedStep(): Step | undefined {
    return this.steps.find((s) => s.status === "failed");
  }

  /** A copy of the report that shares nothing with it, register bytes and dates included. */
  clone(): VerificationReport {
    return construct({
      steps: this.steps,
      ...(this.verifiedFacts === undefined ? {} : { verifiedFacts: copyVerifiedFacts(this.verifiedFacts) }),
      ...(this.partialFacts === undefined ? {} : { partialFacts: this.partialFacts }),
      metadata: this.metadata,
    });
  }

  /** The report as plain JSON: registers as lowercase hex, times as ISO 8601 strings. */
  toJSON(): VerificationReportJSON {
    return {
      steps: this.steps.map((s) => ({ ...s })),
      ...(this.verifiedFacts === undefined ? {} : { verifiedFacts: this.verifiedFacts.toJSON() }),
      ...(this.partialFacts === undefined ? {} : { partialFacts: partialJSON(this.partialFacts) }),
      metadata: { verifier: { ...this.metadata.verifier }, verifiedAt: this.metadata.verifiedAt.toISOString() },
    };
  }
}

/**
 * The fingerprint that {@link MeasuredFacts.hpkePublicKeyFP} reports for
 * `key`, an HPKE public key in lowercase hex as a document endorses it and
 * {@link VerifiedFacts.hpkePublicKey} returns it: the lowercase-hex SHA-256
 * of the key's bytes. Undefined if `key` is empty or not lowercase hex.
 */
export async function hpkePublicKeyFP(key: string): Promise<string | undefined> {
  let raw: Uint8Array;
  try {
    raw = fromHex(key);
  } catch {
    return undefined;
  }
  if (raw.length === 0) return undefined;
  return toHex(await sha256(raw));
}

function copyPartial(p: PartialFacts): PartialFacts {
  return {
    ...(p.expected === undefined ? {} : { expected: copyExpected(p.expected) }),
    ...(p.measured === undefined ? {} : { measured: copyMeasured(p.measured) }),
  };
}

function copyExpected(e: ExpectedFacts): ExpectedFacts {
  return {
    configRepo: e.configRepo,
    artifact: copyArtifact(e.artifact),
    ...(e.config === undefined ? {} : { config: copyConfig(e.config) }),
    ...(e.platform === undefined ? {} : { platform: copyArtifact(e.platform) }),
    ...(e.codeMeasurement === undefined ? {} : { codeMeasurement: cloneExpected(e.codeMeasurement) }),
    ...(e.measurement === undefined ? {} : { measurement: cloneMeasurement(e.measurement) }),
  };
}

function copyMeasured(m: MeasuredFacts): MeasuredFacts {
  return {
    ...(m.cpu === undefined ? {} : { cpu: { measurement: cloneMeasurement(m.cpu.measurement) } }),
    ...(m.tlsPublicKeyFP === undefined ? {} : { tlsPublicKeyFP: m.tlsPublicKeyFP }),
    ...(m.hpkePublicKeyFP === undefined ? {} : { hpkePublicKeyFP: m.hpkePublicKeyFP }),
  };
}

function partialJSON(p: PartialFacts): PartialFactsJSON {
  const e = p.expected;
  const m = p.measured;
  return {
    ...(e === undefined
      ? {}
      : {
          expected: {
            configRepo: e.configRepo,
            artifact: artifactJSON(e.artifact),
            ...(e.config === undefined ? {} : { config: configJSON(e.config) }),
            ...(e.platform === undefined ? {} : { platform: artifactJSON(e.platform) }),
            ...(e.codeMeasurement === undefined ? {} : { codeMeasurement: measurementJSON(e.codeMeasurement) }),
            ...(e.measurement === undefined ? {} : { measurement: measurementJSON(e.measurement) }),
          },
        }),
    ...(m === undefined
      ? {}
      : {
          measured: {
            ...(m.cpu === undefined ? {} : { cpu: { measurement: measurementJSON(m.cpu.measurement) } }),
            ...(m.tlsPublicKeyFP === undefined ? {} : { tlsPublicKeyFP: m.tlsPublicKeyFP }),
            ...(m.hpkePublicKeyFP === undefined ? {} : { hpkePublicKeyFP: m.hpkePublicKeyFP }),
          },
        }),
  };
}

/** The verification layers, in the order that they run. */
const LAYERS: readonly Layer[] = ["envelope", "provenance", "quote", "policy"];

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/**
 * @internal Records each step of a verification as the verifier runs it,
 * and the facts that each step establishes, from values that the verifier
 * already computes.
 */
export class ReportBuilder {
  readonly #steps: Mutable<Step>[] = LAYERS.map((layer) => ({ layer, status: "not_run", message: "" }));
  /** Set once the provenance step passed or was skipped; `measurement` is set later, by the policy step. */
  expected: Mutable<ExpectedFacts> | undefined;
  /** Set once the envelope step passed; `cpu` is set later, by the quote step. */
  measured: Mutable<MeasuredFacts> | undefined;

  set(layer: Layer, status: StepStatus, message: string): void {
    for (const step of this.#steps) {
      if (step.layer === layer) {
        step.status = status;
        step.message = message;
      }
    }
  }

  passed(layer: Layer): void {
    this.set(layer, "passed", "");
  }

  /** The report of a verification that every step accepted. */
  passedAll(verifiedFacts: VerifiedFacts, metadata: VerificationMetadata): VerificationReport {
    return construct({ steps: this.#steps, verifiedFacts, metadata });
  }

  /** The report of a verification that `layer` rejected with `message`. */
  failed(layer: Layer, message: string, metadata: VerificationMetadata): VerificationReport {
    this.set(layer, "failed", message);
    return construct({
      steps: this.#steps,
      partialFacts: {
        ...(this.expected === undefined ? {} : { expected: this.expected }),
        ...(this.measured === undefined ? {} : { measured: this.measured }),
      },
      metadata,
    });
  }
}

/**
 * @internal The key fingerprints that `items` endorse. The envelope checked
 * only that the document is consistent with itself, so they stay
 * unverified until the policy step binds them.
 */
export async function measuredKeys(items: readonly CryptoMaterialItem[]): Promise<Mutable<MeasuredFacts>> {
  const measured: Mutable<MeasuredFacts> = {};
  const tls = cryptoMaterialData(items, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT);
  if (tls !== undefined) measured.tlsPublicKeyFP = tls;
  const hpke = cryptoMaterialData(items, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT);
  const fp = hpke === undefined ? undefined : await hpkePublicKeyFP(hpke);
  if (fp !== undefined) measured.hpkePublicKeyFP = fp;
  return measured;
}
