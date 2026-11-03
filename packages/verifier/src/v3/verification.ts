import { cloneExpected, cloneMeasurement, type Expected, type Measurement } from "./measurement.js";

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
 * The facts proven by verifying an attestation document. Only the verifier
 * creates one, and it can't be changed: the state is runtime-private and
 * accessors return copies.
 * TODO(v3): crypto material, freshness expiry, config/runtime/platform
 * artifacts and metadata.
 */
export class Verification {
  readonly #fields: VerificationFields;

  /** @internal */
  constructor(fields: VerificationFields) {
    this.#fields = {
      ...fields,
      codeMeasurement: cloneExpected(fields.codeMeasurement),
      enclaveMeasurement: cloneMeasurement(fields.enclaveMeasurement),
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

  /** The endorsed TLS SPKI fingerprint, or undefined if the document endorses none in that format. */
  tlsPublicKeyFP(): string | undefined {
    return this.#fields.tlsPublicKeyFP;
  }

  /** The endorsed HPKE (x25519) public key, or undefined if the document endorses none in that format. */
  hpkePublicKey(): string | undefined {
    return this.#fields.hpkePublicKey;
  }
}
