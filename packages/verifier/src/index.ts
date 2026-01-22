export { verifyAttestation, fetchAttestation } from './attestation.js';
export { Verifier } from './client.js';
export { fetchLatestDigest, fetchAttestationBundle } from './github.js';
export { PredicateType, compareMeasurements, measurementFingerprint, AttestationError, FormatMismatchError, MeasurementMismatchError } from './types.js';
export type { AttestationDocument, AttestationMeasurement, AttestationResponse, AttestationBundle, VerificationDocument, VerificationStepState, HardwareMeasurement } from './types.js';
export type { VerifierOptions } from './client.js';
