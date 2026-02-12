// Error classes
export {
  TinfoilError,
  ConfigurationError,
  FetchError,
  AttestationError,
} from './errors.js';

// Verification functions
export { verifyAttestation, fetchAttestation } from './attestation.js';
export { assembleAttestationBundle } from './bundle.js';
export { Verifier } from './client.js';
export { fetchLatestDigest, fetchGithubAttestationBundle } from './github.js';
export { PredicateType, compareMeasurements, measurementFingerprint, hashAttestationDocument } from './types.js';
export type { AttestationDocument, AttestationMeasurement, AttestationResponse, AttestationBundle, VerificationDocument, VerificationStepState, HardwareMeasurement } from './types.js';
export type { VerifierOptions } from './client.js';
export { verifyCertificate, type CertVerificationResult } from './cert-verify.js';
