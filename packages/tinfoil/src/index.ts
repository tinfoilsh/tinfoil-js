// Re-export the TinfoilAI class
export { TinfoilAI } from "./tinfoil-ai.js";
export { TinfoilAI as default } from "./tinfoil-ai.js";

// Export verifier
export * from "./verifier.js";
export * from "./ai-sdk-provider.js";
export * from "./config.js";
export { SecureClient, type TransportMode } from "./secure-client.js";
export { UnverifiedClient } from "./unverified-client.js";
export { fetchRouter } from "./router.js";

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
