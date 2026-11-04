import { CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, type CryptoMaterialItem } from "./document/document.js";
import { cloneExpected, cloneMeasurement, type Expected, type Measurement } from "./measurement.js";

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
   * The registry scope the endorsement was accepted under: the one its
   * certificate assigns, the public scope for a key-signed registry
   * approval, "" when none applies.
   */
  readonly scope: string;
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

/**
 * The facts proven by verifying an attestation document. Only the verifier
 * creates one, and it can't be changed: the state is runtime-private and
 * accessors return copies.
 */
export class Verification {
  readonly #fields: VerificationFields;

  /** @internal */
  constructor(fields: VerificationFields) {
    this.#fields = {
      ...fields,
      codeMeasurement: cloneExpected(fields.codeMeasurement),
      enclaveMeasurement: cloneMeasurement(fields.enclaveMeasurement),
      cryptoMaterial: fields.cryptoMaterial.map((i) => ({ ...i })),
      config: fields.config && copyConfig(fields.config),
      runtime: fields.runtime && { ...fields.runtime, approvalTime: copyDate(fields.runtime.approvalTime) },
      platform: fields.platform && { ...fields.platform, approvalTime: copyDate(fields.platform.approvalTime) },
      freshnessExpiresAt: copyDate(fields.freshnessExpiresAt),
      metadata: { verifier: { ...fields.metadata.verifier }, verifiedAt: new Date(fields.metadata.verifiedAt.getTime()) },
    };
  }

  /** Digest of the verified code or runtime artifact. */
  codeDigest(): string {
    return this.#fields.codeDigest;
  }

  /** Release tag of the verified code or runtime artifact. */
  codeTag(): string {
    return this.#fields.codeTag;
  }

  /** The selected code or runtime repository, without version pins. */
  configRepo(): string {
    return this.#fields.configRepo;
  }

  /** Registers the release fixes on the enclave's platform; unset registers are left to the platform. */
  codeMeasurement(): Expected {
    return cloneExpected(this.#fields.codeMeasurement);
  }

  /** The quote's authenticated registers. */
  enclaveMeasurement(): Measurement {
    return cloneMeasurement(this.#fields.enclaveMeasurement);
  }

  /** The verified config, for a config-based document. */
  config(): ConfigVerification | undefined {
    const c = this.#fields.config;
    return c && copyConfig(c);
  }

  /** The verified runtime release, for a config-based document. */
  runtime(): ArtifactVerification | undefined {
    const r = this.#fields.runtime;
    return r && { ...r, approvalTime: copyDate(r.approvalTime) };
  }

  /** The verified platform endorsements, for a config-based document. */
  platform(): ArtifactVerification | undefined {
    const p = this.#fields.platform;
    return p && { ...p, approvalTime: copyDate(p.approvalTime) };
  }

  /** Every crypto-material item the quote endorsed, as sent. */
  cryptoMaterial(): CryptoMaterialItem[] {
    return this.#fields.cryptoMaterial.map((i) => ({ ...i }));
  }

  /** The data of the endorsed item with the given id and format, or undefined. */
  cryptoMaterialData(id: string, format: string): string | undefined {
    return cryptoMaterialData(this.#fields.cryptoMaterial, id, format);
  }

  /** The endorsed TLS SPKI fingerprint, or undefined if the document endorses none in that format. */
  tlsPublicKeyFP(): string | undefined {
    return this.cryptoMaterialData(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT);
  }

  /** The endorsed HPKE (x25519) public key, or undefined if the document endorses none in that format. */
  hpkePublicKey(): string | undefined {
    return this.cryptoMaterialData(CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT);
  }

  /** When the freshness proofs stop vouching for the document; undefined when none applies. */
  freshnessExpiresAt(): Date | undefined {
    return copyDate(this.#fields.freshnessExpiresAt);
  }

  metadata(): VerificationMetadata {
    const m = this.#fields.metadata;
    return { verifier: { ...m.verifier }, verifiedAt: new Date(m.verifiedAt.getTime()) };
  }
}

/** The data of the first item with the given id and format, or undefined. */
export function cryptoMaterialData(items: readonly CryptoMaterialItem[], id: string, format: string): string | undefined {
  return items.find((i) => i.id === id && i.format === format)?.data;
}

function copyConfig(c: ConfigVerification): ConfigVerification {
  return {
    ...c,
    ...(c.approvalTime === undefined ? {} : { approvalTime: copyDate(c.approvalTime) }),
    ...(c.signatureTime === undefined ? {} : { signatureTime: copyDate(c.signatureTime) }),
  };
}

function copyDate(d: Date | undefined): Date | undefined {
  return d === undefined ? undefined : new Date(d.getTime());
}
