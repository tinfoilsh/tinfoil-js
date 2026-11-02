import type { Expected, Measurement } from "./measurement.js";

/** @internal The facts the verifier proved; only the verifier builds one. */
export interface VerificationFields {
  readonly codeDigest: string;
  readonly codeTag: string;
  readonly configRepo: string;
  readonly codeMeasurement: Expected;
  readonly enclaveMeasurement: Measurement;
  readonly tlsPublicKeyFP?: string;
  readonly hpkePublicKey?: string;
}

/**
 * The facts proven by verifying an attestation document. Immutable; only the
 * verifier creates one.
 * TODO(v3): crypto material, freshness expiry, config/runtime/platform
 * artifacts and metadata (tinfoil-go verify.Verification).
 */
export class Verification {
  /** Digest of the verified code or runtime artifact. */
  readonly codeDigest: string;
  /** Release tag of the verified code or runtime artifact. */
  readonly codeTag: string;
  /** The selected code or runtime repository, without version pins. */
  readonly configRepo: string;
  readonly #fields: VerificationFields;

  /** @internal */
  constructor(fields: VerificationFields) {
    this.#fields = fields;
    this.codeDigest = fields.codeDigest;
    this.codeTag = fields.codeTag;
    this.configRepo = fields.configRepo;
  }

  /** Registers the release fixes on the enclave's platform; unset registers are left to the platform. */
  codeMeasurement(): Expected {
    return this.#fields.codeMeasurement;
  }

  /** The quote's authenticated registers. */
  enclaveMeasurement(): Measurement {
    return this.#fields.enclaveMeasurement;
  }

  /** The endorsed TLS SPKI fingerprint, or undefined if the document endorses none in that format. */
  tlsPublicKeyFP(): string | undefined {
    return this.#fields.tlsPublicKeyFP;
  }

  /** The endorsed HPKE (x25519) public key, or undefined if the document endorses none in that format. */
  hpkePublicKey(): string | undefined {
    return this.#fields.hpkePublicKey;
  }
}
