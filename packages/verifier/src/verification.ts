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
export interface VerifiedFactsFields {
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
}

/**
 * A measurement in the report's JSON form: the platform, and each register
 * that it holds as lowercase hex. A code measurement leaves out the
 * registers that the release leaves to the platform.
 */
export type MeasurementJSON =
  | { readonly platform: "sev-snp"; readonly launch?: string }
  | { readonly platform: "tdx"; readonly mrtd?: string; readonly rtmr0?: string; readonly rtmr1?: string; readonly rtmr2?: string; readonly rtmr3?: string };

/**
 * A {@link ConfigVerification} in the report's JSON form, with times as RFC
 * 3339 strings in UTC. A member that the config doesn't have, such as the
 * reference of a config that no endorsement supplied, is left out.
 */
export interface ConfigVerificationJSON {
  readonly source: ReferenceSource;
  readonly name?: string;
  readonly digest: string;
  readonly reference?: string;
  readonly signing_key_hint?: string;
  readonly approval_time?: string;
  readonly registry_id?: string;
  readonly signature_time?: string;
}

/**
 * An {@link ArtifactVerification} in the report's JSON form, with its time
 * as an RFC 3339 string in UTC. A member that the artifact doesn't have,
 * such as the name of an embedded artifact, is left out.
 */
export interface ArtifactVerificationJSON {
  readonly source: ReferenceSource;
  readonly repo?: string;
  readonly tag?: string;
  readonly digest: string;
  readonly name?: string;
  readonly commit?: string;
  readonly approval_time?: string;
}

/**
 * The `verified_facts` object of the report's JSON form, as
 * {@link VerifiedFacts.toJSON} returns it. The channel keys appear only in
 * `crypto_material`.
 */
export interface VerifiedFactsJSON {
  readonly config_repo: string;
  readonly code_digest: string;
  readonly code_tag?: string;
  /** Left out when the release fixes no register on the enclave's platform. */
  readonly code_measurement?: MeasurementJSON;
  readonly enclave_measurement: MeasurementJSON;
  readonly config?: ConfigVerificationJSON;
  readonly runtime?: ArtifactVerificationJSON;
  readonly platform?: ArtifactVerificationJSON;
  readonly crypto_material: readonly CryptoMaterialItem[];
  readonly freshness_expires_at?: string;
}

/** The `metadata` object of the report's JSON form. */
export interface VerificationMetadataJSON {
  /** The appraisal instant, as an RFC 3339 string in UTC. */
  readonly verified_at: string;
  /** The name and version of the SDK that verified the document. */
  readonly verifier?: { readonly name: string; readonly version: string };
}

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const BUILT_HERE: unique symbol = Symbol("VerifiedFacts");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (fields: VerifiedFactsFields) => VerifiedFacts;

/**
 * The facts proven by verifying an attestation document, including the
 * channel keys that a caller binds its traffic to: the `verifiedFacts` of
 * the {@link VerificationReport} of a document that the verifier accepted.
 * They are the only source of channel keys. Only the verifier creates them:
 * the constructor is private, so type-checked code cannot construct them,
 * and a call from untyped code is refused at runtime by a token that only
 * this module holds. Every fact is a `readonly` property
 * whose value is fixed at construction: the instance and every nested
 * object and array are frozen, so a property always yields the same
 * reference and nothing on it can be reassigned. Register bytes
 * (`Uint8Array`) and `Date` values have no frozen form in the language; they
 * are shared as stored and must not be mutated. `toJSON()` gives the facts
 * in the JSON form that every Tinfoil SDK exports, for display and
 * transport; that JSON authorizes nothing.
 */
export class VerifiedFacts {
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

  private constructor(token: typeof BUILT_HERE, fields: VerifiedFactsFields) {
    if (token !== BUILT_HERE) throw new UsageError("verified facts come from a verifier: verify a document to get them");
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
    Object.freeze(this);
  }

  static {
    construct = (fields) => new VerifiedFacts(BUILT_HERE, fields);
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

  /**
   * The facts as the `verified_facts` object of the report's JSON form, the
   * form that every Tinfoil SDK exports, so that `JSON.stringify(facts)`
   * writes it: snake_case members, registers and digests as lowercase hex,
   * times as RFC 3339 strings in UTC, and facts that were not established
   * left out. A code measurement holds only the registers that the release
   * fixes, and is left out when it fixes none.
   *
   * The JSON is for display and transport, and it authorizes nothing: this
   * package reads nothing back from it, and a holder of the JSON can't tell
   * whether a verifier wrote it. Bind a channel only to the keys of facts
   * that a verification returned.
   */
  toJSON(): VerifiedFactsJSON {
    const code = codeMeasurementJSON(this.codeMeasurement);
    return {
      config_repo: this.configRepo,
      code_digest: this.codeDigest,
      ...stringJSON("code_tag", this.codeTag),
      ...(code === undefined ? {} : { code_measurement: code }),
      enclave_measurement: measurementJSON(this.enclaveMeasurement),
      ...(this.config === undefined ? {} : { config: configJSON(this.config) }),
      ...(this.runtime === undefined ? {} : { runtime: artifactJSON(this.runtime) }),
      ...(this.platform === undefined ? {} : { platform: artifactJSON(this.platform) }),
      crypto_material: this.cryptoMaterial.map((i) => ({ id: i.id, format: i.format, data: i.data })),
      ...timeJSON("freshness_expires_at", this.freshnessExpiresAt),
    };
  }
}

/** @internal The facts that the verifier proved, as a {@link VerifiedFacts}; the verifier is its only caller. */
export function verifiedFactsOf(fields: VerifiedFactsFields): VerifiedFacts {
  return construct(fields);
}

/** @internal A copy of `v` that shares no register bytes or dates with it. */
export function copyVerifiedFacts(v: VerifiedFacts): VerifiedFacts {
  // The constructor copies every field that it is given.
  return construct(v);
}

/** The data of the first item with the given id and format, or undefined. */
export function cryptoMaterialData(items: readonly CryptoMaterialItem[], id: string, format: string): string | undefined {
  return items.find((i) => i.id === id && i.format === format)?.data;
}

/** @internal Freezes a plain object or array and everything reachable through it; byte views and dates are left as they are. */
export function freezeDeep<T>(value: T): T {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value) || value instanceof Date) return value;
  for (const nested of Object.values(value)) freezeDeep(nested);
  return Object.freeze(value);
}

/** @internal */
export function copyConfig(c: ConfigVerification): ConfigVerification {
  return {
    ...c,
    ...(c.approvalTime === undefined ? {} : { approvalTime: copyDate(c.approvalTime) }),
    ...(c.signatureTime === undefined ? {} : { signatureTime: copyDate(c.signatureTime) }),
  };
}

/** @internal */
export function copyArtifact(a: ArtifactVerification): ArtifactVerification {
  return { ...a, ...(a.approvalTime === undefined ? {} : { approvalTime: copyDate(a.approvalTime) }) };
}

/** @internal */
export function copyDate(d: Date | undefined): Date | undefined {
  return d === undefined ? undefined : new Date(d.getTime());
}

/** @internal A measurement or expectation in the report's JSON form; an unset register is left out. */
export function measurementJSON(m: Measurement | Expected): MeasurementJSON {
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

/** @internal A code measurement in the report's JSON form, or undefined when it holds no register, so that it is left out. */
export function codeMeasurementJSON(e: Expected): MeasurementJSON | undefined {
  const out = measurementJSON(e);
  return Object.keys(out).length > 1 ? out : undefined;
}

/** @internal */
export function configJSON(c: ConfigVerification): ConfigVerificationJSON {
  return {
    source: c.source,
    ...stringJSON("name", c.name),
    digest: c.digest,
    ...stringJSON("reference", c.reference),
    ...stringJSON("signing_key_hint", c.signingKeyHint),
    ...timeJSON("approval_time", c.approvalTime),
    ...stringJSON("registry_id", c.registryID),
    ...timeJSON("signature_time", c.signatureTime),
  };
}

/** @internal */
export function artifactJSON(a: ArtifactVerification): ArtifactVerificationJSON {
  return {
    source: a.source,
    ...stringJSON("repo", a.repo),
    ...stringJSON("tag", a.tag),
    digest: a.digest,
    ...stringJSON("name", a.name),
    ...stringJSON("commit", a.commit),
    ...timeJSON("approval_time", a.approvalTime),
  };
}

/** `{ [key]: hex }` for a set register, `{}` for an unset one. */
function hexJSON<K extends string>(key: K, r: Register | undefined): { readonly [P in K]?: string } {
  return r === undefined ? {} : ({ [key]: registerHex(r) } as { [P in K]?: string });
}

/** @internal `{ [key]: s }` for a non-empty string, `{}` for an empty or absent one, since the JSON form never holds "". */
export function stringJSON<K extends string>(key: K, s: string | undefined): { readonly [P in K]?: string } {
  return s === undefined || s === "" ? {} : ({ [key]: s } as { [P in K]?: string });
}

/** @internal An instant as an RFC 3339 string in UTC, without a fraction when it falls on a whole second. */
export function rfc3339(d: Date): string {
  return d.toISOString().replace(/\.000Z$/, "Z");
}

/** @internal `{ [key]: time }` for a set time, `{}` for an unset one. */
export function timeJSON<K extends string>(key: K, d: Date | undefined): { readonly [P in K]?: string } {
  return d === undefined ? {} : ({ [key]: rfc3339(d) } as { [P in K]?: string });
}
