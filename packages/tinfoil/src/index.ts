// Re-export the TinfoilAI class
export { TinfoilAI } from "./tinfoil-ai.js";
export { TinfoilAI as default } from "./tinfoil-ai.js";
export type { TinfoilAIOptions } from "./tinfoil-ai.js";

export {
  TinfoilError,
  ConfigurationError,
  AttestationError,
  Verifier,
  assembleAttestationBundle,
} from "./verifier.js";

export type {
  AttestationDocument,
  AttestationMeasurement,
  AttestationResponse,
  AttestationBundle,
  VerificationDocument,
  VerificationStepState,
  HardwareMeasurement,
  VerifierOptions,
  CertVerificationResult,
} from "./verifier.js";
export { createTinfoilAI } from "./ai-sdk-provider.js";
export type { CreateTinfoilAIOptions } from "./ai-sdk-provider.js";
export { SecureClient, type TransportMode } from "./secure-client.js";
export type { SessionRecoveryToken } from "ehbp";
export { UnverifiedClient } from "./unverified-client.js";
export { fetchRouter, fetchAttestationBundle, type FetchAttestationBundleOptions } from "./atc.js";

// Re-export OpenAI utility types and classes that users might need
// Using public exports from the main OpenAI package instead of deep imports
export {
  type Uploadable,
  toFile,
  APIPromise,
  PagePromise,
  OpenAIError,
  APIError,
  APIConnectionError,
  APIConnectionTimeoutError,
  APIUserAbortError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  BadRequestError,
  AuthenticationError,
  InternalServerError,
  PermissionDeniedError,
  UnprocessableEntityError,
} from "openai";
