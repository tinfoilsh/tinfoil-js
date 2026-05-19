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
export { PredicateType, compareMeasurements, measurementFingerprint, measurementFingerprintForTarget, hashAttestationDocument } from './types.js';
export type { AttestationDocument, AttestationMeasurement, AttestationResponse, AttestationBundle, VerificationDocument, VerificationStepState, HardwareMeasurement } from './types.js';
export type { VerifierOptions } from './client.js';
export { verifyCertificate, type CertVerificationResult } from './cert-verify.js';

// Sigstore mid-level entry point + policy (used by the SDK's standard path
// and the cross-SDK conformance binary).
export {
  verifySigstoreBundle,
  verifySigstoreBundleWithPolicy,
  defaultSigstorePolicy,
} from './sigstore.js';
export type {
  SigstorePolicy,
  SigstoreVerification,
} from './sigstore.js';
