// Error classes
export {
  TinfoilError,
  ConfigurationError,
  FetchError,
  AttestationError,
} from './errors.js';

// Verification
export { verifyAttestation } from './attestation.js';
export { assembleAttestationBundle, fetchEnclaveAttestationMaterial, type EnclaveAttestationMaterial } from './bundle.js';
export { Verifier, PINNED_NO_REPO, PINNED_NO_DIGEST, type VerifiableAttestationBundle } from './client.js';
export { cloneVerificationDocument } from './json.js';
export { VERIFICATION_DOCUMENT_SCHEMA_VERSION, VERIFIER_NAME, VERIFIER_VERSION } from './version.js';
export { PredicateType, compareMeasurements, measurementFingerprint, hashAttestationDocument } from './types.js';
export type { AttestationDocument, AttestationMeasurement, AttestationResponse, AttestationBundle, VerificationDocument, VerificationStepState, HardwareMeasurement, SoftwareIdentity } from './types.js';
export type { VerifierOptions } from './client.js';
export { verifyCertificate, type CertVerificationResult } from './cert-verify.js';
