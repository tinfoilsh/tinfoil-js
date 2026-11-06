/**
 * The public surface of the v3 verifier: the verifier and its options, the
 * facts a verification proves, the error types, the measurement types, the
 * document constants a caller needs to fetch a document and read endorsed
 * keys, and the TLS fingerprint helper. Nothing else in this package is
 * supported for direct use.
 */
import { UsageError } from "./errors.js";
import { PUBLIC_REGISTRY_ID as PUBLIC_REGISTRY_ID_INTERNAL } from "./internal/endorsement/approval.js";
import { parseReference as parseReferenceInternal, type Reference } from "./internal/endorsement/reference.js";
import { parseCertificate, spkiFingerprint, X509Error } from "./internal/x509/certificate.js";
import { DerError } from "./internal/x509/der.js";
import {
  parseExpectedSevSnp as parseExpectedSevSnpInternal,
  parseExpectedTdx as parseExpectedTdxInternal,
  parseRegister as parseRegisterInternal,
  type ExpectedSevSnp,
  type ExpectedTdx,
  type Register,
} from "./measurement.js";

export { Verifier, type EmbeddedConfigBytes, type EmbeddedConfigReference, type EmbeddedReferences, type VerifierOptions } from "./verifier.js";
export {
  cryptoMaterialData,
  Verification,
  type ArtifactVerification,
  type ArtifactVerificationJSON,
  type ConfigVerification,
  type ConfigVerificationJSON,
  type MeasurementJSON,
  type ReferenceSource,
  type VerificationJSON,
  type VerificationMetadata,
} from "./verification.js";
export type { ConfigEndorsement } from "./document/collateral/config.js";
export type { RuntimeReference } from "./document/collateral/runtime.js";
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
// The measurement module's parse functions throw bare errors for the
// pipeline to classify; the entry exports versions that throw UsageError.
export {
  cloneExpected,
  cloneMeasurement,
  expectedOf,
  formatMeasurement,
  REGISTER_SIZE,
  registerHex,
  type Expected,
  type ExpectedSevSnp,
  type ExpectedTdx,
  type Measurement,
  type Register,
  type SevSnpMeasurement,
  type TdxMeasurement,
} from "./measurement.js";
export type { Reference };

/**
 * The public registry's ID, the one accepted by default. `configRegistryIDs`
 * names the exact accepted set, so a policy that accepts the public registry
 * alongside others lists it: `[PUBLIC_REGISTRY_ID, ...mine]`.
 */
export const PUBLIC_REGISTRY_ID: string = PUBLIC_REGISTRY_ID_INTERNAL;

/** Runs a check on caller input; its failure is a UsageError with the original error as `cause`. */
function usage<T>(check: () => T): T {
  try {
    return check();
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err), { cause: err });
  }
}

/** Validates `owner/name[@tag][@sha256:digest]` and returns its parts, "" for an absent part. Throws UsageError. */
export function parseReference(ref: string): Reference {
  return usage(() => parseReferenceInternal(ref));
}

/** Decodes a register from hex in either case. Throws UsageError for bad hex or length. */
export function parseRegister(s: string): Register {
  return usage(() => parseRegisterInternal(s));
}

/** Parses an SEV-SNP expectation; "" leaves the launch register unconstrained. Throws UsageError for a bad register. */
export function parseExpectedSevSnp(launch: string): ExpectedSevSnp {
  return usage(() => parseExpectedSevSnpInternal(launch));
}

/** Parses a TDX expectation; "" leaves that register unconstrained. Throws UsageError for a bad register. */
export function parseExpectedTdx(mrtd: string, rtmr0: string, rtmr1: string, rtmr2: string, rtmr3: string): ExpectedTdx {
  return usage(() => parseExpectedTdxInternal(mrtd, rtmr0, rtmr1, rtmr2, rtmr3));
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
