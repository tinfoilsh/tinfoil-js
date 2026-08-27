// Error classes
export {
  TinfoilError,
  ConfigurationError,
  FetchError,
  AttestationError,
} from './errors.js';

// Verification
export { verifyAttestation } from './attestation.js';
export { assembleAttestationBundle } from './bundle.js';
export { Verifier } from './client.js';
export { cloneVerificationDocument } from './json.js';
export { VERIFICATION_DOCUMENT_SCHEMA_VERSION, VERIFIER_NAME, VERIFIER_VERSION } from './version.js';
export { PredicateType, compareMeasurements, measurementFingerprint, hashAttestationDocument } from './types.js';
export type { AttestationDocument, AttestationMeasurement, AttestationResponse, AttestationBundle, VerificationDocument, VerificationStepState, HardwareMeasurement, SoftwareIdentity } from './types.js';
export type { VerifierOptions } from './client.js';
export { verifyCertificate, type CertVerificationResult } from './cert-verify.js';

// v3 verification (Tier-1 public surface, SDK_SURFACE_SPEC v1.0.0).
// Curated: `export * from './v3'` would collide with legacy names.
export { verifyDocumentV3, tlsPublicKeyFP, hpkePublicKey } from './v3/client.js';
export { fetchAttestation, randomNonce } from './v3/fetch.js';
export { NonceSize } from './v3/envelope.js';
export { VerificationError } from './v3/errors.js';
export type { VerifiedDocumentV3, VerifyOpts } from './v3/client.js';
export type { RejectionLayer } from './v3/errors.js';
