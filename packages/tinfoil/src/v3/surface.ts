/**
 * The public surface of the client: the names every entry point exports.
 * The Node and browser entries re-export this module; a platform-specific
 * behaviour lives behind the same names.
 */
export { EnclaveHTTPClient } from "./enclave-client.js";
export { RouterHTTPClient } from "./router-client.js";
export { GatewayHTTPClient, fetchCatalog } from "./gateway-client.js";
export { TinfoilClient, createClient, EnclaveOpenAIClient, RouterOpenAIClient, GatewayOpenAIClient, type OpenAIOptions } from "./openai-client.js";
export { TinfoilError, ConfigurationError, NetworkError, AttestationError, type ErrorCategory } from "./errors.js";
export {
  sessionRecoveryToken,
  serializeSessionRecoveryToken,
  deserializeSessionRecoveryToken,
  decryptResponseWithToken,
  type SessionRecoveryToken,
} from "./session-recovery.js";
export type {
  Fetch,
  TransportMode,
  VerificationCheck,
  EnclaveOptions,
  RouterOptions,
  GatewayOptions,
  ModelPin,
  Catalog,
  CatalogEntry,
  ReplicaVerification,
} from "./options.js";
export { SDK_VERSION } from "../version.js";

// The OpenAI helpers and error types callers need alongside the clients.
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
