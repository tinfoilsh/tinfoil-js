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
export { PredicateType, compareMeasurements, measurementFingerprint, hashAttestationDocument } from './types.js';
export type { AttestationDocument, AttestationMeasurement, AttestationResponse, AttestationBundle, VerificationDocument, VerificationStepState, HardwareMeasurement } from './types.js';
export { verifyHardware } from './hardware.js';
export { fetchHardwareMeasurements } from './sigstore.js';
export type { VerifierOptions } from './client.js';
export { verifyCertificate, type CertVerificationResult } from './cert-verify.js';

// TDX exports
export { parseTdxQuote } from './tdx/quote.js';
export type { TdxQuote, TdxQuoteHeader, TdQuoteBody, QeReport } from './tdx/quote.js';
export { validateTdxQuote, defaultTdxValidationOptions } from './tdx/validation.js';
export type { TdxValidationOptions } from './tdx/validation.js';
export { parsePckExtensions } from './tdx/pck-extensions.js';
export type { PckExtensions } from './tdx/pck-extensions.js';
export { validateCollateral } from './tdx/collateral.js';
export type { CollateralOptions } from './tdx/collateral.js';
