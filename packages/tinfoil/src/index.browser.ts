export { TinfoilAI, TinfoilAI as default, type TinfoilAIOptions } from "./tinfoil-ai.js";
export { TinfoilError, ConfigurationError, AttestationError, NetworkError } from "./errors.js";
export { SecureClient, type SecureClientOptions, type VerificationSnapshot, type TransportMode, type SecureWebSocketOptions } from "./secure-client.js";
export { Client, type ClientOptions } from "./client.js";
export { Gateway, type GatewayOptions, type Catalog, type CatalogEntry, type ModelPin } from "./gateway.js";
export { createTinfoilAI, type CreateTinfoilAIOptions } from "./ai-sdk-provider.js";
export { fetchAttestationDocument, fetchRouters, type AcquisitionOptions } from "./acquisition.js";
export type { SessionRecoveryToken } from "ehbp";
export { serializeSessionRecoveryToken, deserializeSessionRecoveryToken, decryptResponseWithToken } from "ehbp";

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
