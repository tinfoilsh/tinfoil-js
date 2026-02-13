// Browser entry point - uses same consolidated modules as server
// Runtime detection in secure-fetch.ts handles browser-specific behavior
export { TinfoilAI } from "./tinfoil-ai.js";
export { TinfoilAI as default } from "./tinfoil-ai.js";
export type { TinfoilAIOptions } from "./tinfoil-ai.js";

export * from "./verifier.js";
export * from "./ai-sdk-provider.js";
export * from "./config.js";
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
