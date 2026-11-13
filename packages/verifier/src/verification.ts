import { CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, type CryptoMaterialItem } from "./document/document.js";
import { UsageError } from "./errors.js";
import { cloneExpected, cloneMeasurement, registerHex, type Expected, type Measurement, type Register } from "./measurement.js";

/** Where a reference value came from: a verified endorsement, caller-embedded references, or caller policy. */
export type ReferenceSource = "endorsement" | "embedded" | "policy";

/** The verified config of a config-based document. */
export interface ConfigVerification {
  readonly source: ReferenceSource;
  /** The versioned config name, when endorsed. */
  readonly name: string;
  /** Lowercase hex SHA-256 of the config bytes. */
  readonly digest: string;
  /** The endorsement reference, when endorsed. */
  readonly reference: string;
  readonly signingKeyHint: string;
  /** Undefined when the config was not approved by a timestamped endorsement. */
  readonly approvalTime?: Date;
  /**
   * The registry ID the endorsement was accepted under: the one its
   * certificate assigns, the public registry ID for a key-signed registry
   * approval, "" when none applies.
   */
  readonly registryID: string;
  /** When a certificate-signed approval's signature was made; undefined otherwise. */
  readonly signatureTime?: Date;
}

/** A verified release artifact: the runtime or the platform endorsements. */
export interface ArtifactVerification {
  readonly source: ReferenceSource;
  readonly repo: string;
  readonly tag: string;
  readonly digest: string;
  readonly name: string;
  readonly commit: string;
  /** Undefined when no freshness approval was consulted. */
  readonly approvalTime?: Date;
}

export interface VerificationMetadata {
  readonly verifier: { readonly name: string; readonly version: string };
  readonly verifiedAt: Date;
}

/** @internal The facts the verifier proved; only the verifier builds one. */
export interface VerificationFields {
  readonly codeDigest: string;
  readonly codeTag: string;
  readonly configRepo: string;
  readonly codeMeasurement: Expected;
  readonly enclaveMeasurement: Measurement;
  readonly cryptoMaterial: readonly CryptoMaterialItem[];
  readonly config?: ConfigVerification;
  readonly runtime?: ArtifactVerification;
  readonly platform?: ArtifactVerification;
  readonly freshnessExpiresAt?: Date;
  readonly metadata: VerificationMetadata;
}

/** A measurement or expectation with each set register as lowercase hex. */
export type MeasurementJSON =
  | { readonly platform: "sev-snp"; readonly launch?: string }
  | { readonly platform: "tdx"; readonly mrtd?: string; readonly rtmr0?: string; readonly rtmr1?: string; readonly rtmr2?: string; readonly rtmr3?: string };

/** A `ConfigVerification` with its times as ISO 8601 strings. */
export type ConfigVerificationJSON = Omit<ConfigVerification, "approvalTime" | "signatureTime"> & { readonly approvalTime?: string; readonly signatureTime?: string };

/** An `ArtifactVerification` with its time as an ISO 8601 string. */
export type ArtifactVerificationJSON = Omit<ArtifactVerification, "approvalTime"> & { readonly approvalTime?: string };

/**
 * The JSON form of a `Verification`, as `toJSON()` returns it and
 * `JSON.stringify` serializes it: the same fields as the properties, with
 * registers as lowercase hex and times as ISO 8601 strings. Facts that were
 * not established are left out.
 */
export interface VerificationJSON {
  readonly codeDigest: string;
  readonly codeTag: string;
  readonly configRepo: string;
  readonly codeMeasurement: MeasurementJSON;
  readonly enclaveMeasurement: MeasurementJSON;
  readonly cryptoMaterial: readonly CryptoMaterialItem[];
  readonly config?: ConfigVerificationJSON;
  readonly runtime?: ArtifactVerificationJSON;
  readonly platform?: ArtifactVerificationJSON;
  readonly freshnessExpiresAt?: string;
  readonly metadata: { readonly verifier: VerificationMetadata["verifier"]; readonly verifiedAt: string };
}

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const BUILT_HERE: unique symbol = Symbol("Verification");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (fields: VerificationFields) => Verification;

/**
 * The facts proven by verifying an attestation document. Only the verifier
 * creates one: the constructor is private, so type-checked code cannot
 * construct a verification, and a call from untyped code is refused at
 * runtime by a token only this module holds. Every fact is a `readonly` property
 * whose value is fixed at construction: the instance and every nested
 * object and array are frozen, so a property always yields the same
 * reference and nothing on it can be reassigned. Register bytes
 * (`Uint8Array`) and `Date` values have no frozen form in the language; they
 * are shared as stored and must not be mutated. `toJSON()` gives a plain,
 * serializable copy for logging or persisting.
 */
export class Verification {
  /** Digest of the verified code or runtime artifact. */
  readonly codeDigest: string;
  /** Release tag of the verified code or runtime artifact. */
  readonly codeTag: string;
  /** The selected code or runtime repository, without version pins. */
  readonly configRepo: string;
  /** Registers the release fixes on the enclave's platform; unset registers are left to the platform. */
  readonly codeMeasurement: Expected;
  /** The quote's authenticated registers. */
  readonly enclaveMeasurement: Measurement;
  /** Every crypto-material item the quote endorsed, as sent. */
  readonly cryptoMaterial: readonly CryptoMaterialItem[];
  /** The verified config, for a config-based document. */
  readonly config?: ConfigVerification;
  /** The verified runtime release, for a config-based document. */
  readonly runtime?: ArtifactVerification;
  /** The verified platform endorsements, for a config-based document. */
  readonly platform?: ArtifactVerification;
  /** Earliest approval/freshness timestamp plus the maximum age, capped by CPU collateral validity. */
  readonly freshnessExpiresAt?: Date;
  /** The verifier's name and version, and when it ran. */
  readonly metadata: VerificationMetadata;

  private constructor(token: typeof BUILT_HERE, fields: VerificationFields) {
    if (token !== BUILT_HERE) throw new UsageError("a Verification comes from a verifier: verify a document to get one");
    this.codeDigest = fields.codeDigest;
    this.codeTag = fields.codeTag;
    this.configRepo = fields.configRepo;
    this.codeMeasurement = freezeDeep(cloneExpected(fields.codeMeasurement));
    this.enclaveMeasurement = freezeDeep(cloneMeasurement(fields.enclaveMeasurement));
    this.cryptoMaterial = freezeDeep(fields.cryptoMaterial.map((i) => ({ ...i })));
    this.config = fields.config && freezeDeep(copyConfig(fields.config));
    this.runtime = fields.runtime && freezeDeep(copyArtifact(fields.runtime));
    this.platform = fields.platform && freezeDeep(copyArtifact(fields.platform));
    this.freshnessExpiresAt = copyDate(fields.freshnessExpiresAt);
    this.metadata = freezeDeep({ verifier: { ...fields.metadata.verifier }, verifiedAt: new Date(fields.metadata.verifiedAt.getTime()) });
    Object.freeze(this);
  }

  static {
    construct = (fields) => new Verification(BUILT_HERE, fields);
  }

  /** The data of the endorsed item with the given id and format, or undefined. */
  cryptoMaterialData(id: string, format: string): string | undefined {
    return cryptoMaterialData(this.cryptoMaterial, id, format);
  }

  /** The endorsed TLS SPKI fingerprint, or undefined if the document endorses none in that format. */
  get tlsPublicKeyFP(): string | undefined {
    return this.cryptoMaterialData(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT);
  }

  /** The endorsed HPKE (x25519) public key, or undefined if the document endorses none in that format. */
  get hpkePublicKey(): string | undefined {
    return this.cryptoMaterialData(CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT);
  }

  /** The facts as plain JSON: registers as lowercase hex, times as ISO 8601 strings. */
  toJSON(): VerificationJSON {
    return {
      codeDigest: this.codeDigest,
      codeTag: this.codeTag,
      configRepo: this.configRepo,
      codeMeasurement: measurementJSON(this.codeMeasurement),
      enclaveMeasurement: measurementJSON(this.enclaveMeasurement),
      cryptoMaterial: this.cryptoMaterial.map((i) => ({ ...i })),
      ...(this.config === undefined ? {} : { config: configJSON(this.config) }),
      ...(this.runtime === undefined ? {} : { runtime: artifactJSON(this.runtime) }),
      ...(this.platform === undefined ? {} : { platform: artifactJSON(this.platform) }),
      ...timeJSON("freshnessExpiresAt", this.freshnessExpiresAt),
      metadata: { verifier: { ...this.metadata.verifier }, verifiedAt: this.metadata.verifiedAt.toISOString() },
    };
  }
}

/** @internal The verification of the facts the verifier proved; the verifier is its only caller. */
export function verificationOf(fields: VerificationFields): Verification {
  return construct(fields);
}

/** The data of the first item with the given id and format, or undefined. */
export function cryptoMaterialData(items: readonly CryptoMaterialItem[], id: string, format: string): string | undefined {
  return items.find((i) => i.id === id && i.format === format)?.data;
}

/** Freezes a plain object or array and everything reachable through it; byte views and dates are left as they are. */
function freezeDeep<T>(value: T): T {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value) || value instanceof Date) return value;
  for (const nested of Object.values(value)) freezeDeep(nested);
  return Object.freeze(value);
}

function copyConfig(c: ConfigVerification): ConfigVerification {
  return {
    ...c,
    ...(c.approvalTime === undefined ? {} : { approvalTime: copyDate(c.approvalTime) }),
    ...(c.signatureTime === undefined ? {} : { signatureTime: copyDate(c.signatureTime) }),
  };
}

function copyArtifact(a: ArtifactVerification): ArtifactVerification {
  return { ...a, ...(a.approvalTime === undefined ? {} : { approvalTime: copyDate(a.approvalTime) }) };
}

function copyDate(d: Date | undefined): Date | undefined {
  return d === undefined ? undefined : new Date(d.getTime());
}

function measurementJSON(m: Measurement | Expected): MeasurementJSON {
  switch (m.platform) {
    case "sev-snp":
      return { platform: "sev-snp", ...hexJSON("launch", m.launch) };
    case "tdx":
      return {
        platform: "tdx",
        ...hexJSON("mrtd", m.mrtd),
        ...hexJSON("rtmr0", m.rtmr0),
        ...hexJSON("rtmr1", m.rtmr1),
        ...hexJSON("rtmr2", m.rtmr2),
        ...hexJSON("rtmr3", m.rtmr3),
      };
  }
}

function configJSON(c: ConfigVerification): ConfigVerificationJSON {
  const { approvalTime, signatureTime, ...rest } = c;
  return { ...rest, ...timeJSON("approvalTime", approvalTime), ...timeJSON("signatureTime", signatureTime) };
}

function artifactJSON(a: ArtifactVerification): ArtifactVerificationJSON {
  const { approvalTime, ...rest } = a;
  return { ...rest, ...timeJSON("approvalTime", approvalTime) };
}

/** `{ [key]: hex }` for a set register, `{}` for an unset one. */
function hexJSON<K extends string>(key: K, r: Register | undefined): { readonly [P in K]?: string } {
  return r === undefined ? {} : ({ [key]: registerHex(r) } as { [P in K]?: string });
}

/** `{ [key]: iso }` for a set time, `{}` for an unset one. */
function timeJSON<K extends string>(key: K, d: Date | undefined): { readonly [P in K]?: string } {
  return d === undefined ? {} : ({ [key]: d.toISOString() } as { [P in K]?: string });
}
