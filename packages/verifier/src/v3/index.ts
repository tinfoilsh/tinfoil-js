/**
 * The public surface of the v3 verifier: the verifier and its options, the
 * facts a verification proves, the error types, the measurement types, the
 * document constants a caller needs to fetch a document and read endorsed
 * keys, and the TLS fingerprint helper. Nothing else in this package is
 * supported for direct use.
 */
import { UsageError } from "./errors.js";
import { parseReference as parseReferenceInternal, type Reference } from "./internal/endorsement/reference.js";
import { parseCertificate, spkiFingerprint, X509Error } from "./internal/x509/certificate.js";
import { DerError } from "./internal/x509/der.js";

export { Verifier, type EmbeddedReferences, type VerifierOptions } from "./verifier.js";
export { cryptoMaterialData, Verification, type ArtifactVerification, type ConfigVerification, type ReferenceSource, type VerificationMetadata } from "./verification.js";
export type { ConfigEndorsement } from "./document/collateral/config.js";
export { UsageError, VerificationError, VerifyError, type Layer } from "./errors.js";
export {
  ATTESTATION_V3_FORMAT,
  CRYPTO_MATERIAL_ID_HPKE,
  CRYPTO_MATERIAL_ID_TLS,
  CRYPTO_MATERIAL_V1_FORMAT,
  DEVICE_EVIDENCE_V1_FORMAT,
  KEY_SPKI_FP_SHA256_V1_FORMAT,
  KEY_SPKI_V1_FORMAT,
  KEY_X25519_HPKE_V1_FORMAT,
  NONCE_SIZE,
  NVIDIA_GPU_EVIDENCE_V1_FORMAT,
  randomNonce,
  REPORT_DATA_V1_ALGORITHM,
  SEV_SNP_REPORT_V1_FORMAT,
  TDX_QUOTE_V1_FORMAT,
  type CryptoMaterialItem,
} from "./document/document.js";
export * from "./measurement.js";
export type { Reference };

/** Validates `owner/name[@tag][@sha256:digest]` and returns its parts, "" for an absent part. Throws UsageError. */
export function parseReference(ref: string): Reference {
  try {
    return parseReferenceInternal(ref);
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err), { cause: err });
  }
}

/**
 * The SHA-256 of a DER certificate's SubjectPublicKeyInfo, lowercase hex: the
 * form the endorsed TLS key takes, for pinning a connection to it. Throws
 * UsageError for bytes that are not a certificate.
 */
export async function certPubkeyFP(certDer: Uint8Array): Promise<string> {
  let spki: Uint8Array;
  try {
    spki = parseCertificate(certDer).spki;
  } catch (err) {
    if (err instanceof X509Error || err instanceof DerError) throw new UsageError(`parsing certificate: ${err.message}`, { cause: err });
    throw err;
  }
  return spkiFingerprint(spki);
}
