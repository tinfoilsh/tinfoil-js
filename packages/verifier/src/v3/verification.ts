import type { Expected, Measurement } from "./measurement.js";

/**
 * The verified facts of an accepted document.
 * TODO(v3): config/runtime/platform artifacts, crypto material, freshness
 * expiry and metadata, per tinfoil-go verify.Verification.
 */
export interface Verification {
  /** Digest of the authenticated code release. */
  readonly codeDigest: string;
  /** Registers the release fixes, in the layout of the enclave's platform. */
  readonly codeMeasurement: Expected;
  /** The registers the quote measured. */
  readonly enclaveMeasurement: Measurement;
  /** The endorsed TLS SPKI fingerprint, if the document endorses one. */
  readonly tlsPublicKeyFP?: string;
  /** The endorsed HPKE (x25519) public key, if the document endorses one. */
  readonly hpkePublicKey?: string;
}
