/**
 * Attested HTTP clients without the OpenAI or AI SDK adapters. This entry
 * shares the root entry's clients, verification, transports and lifecycle;
 * the package's browser mappings select EHBP-only implementations in a page.
 */
export { EnclaveHTTPClient } from "./enclave-client.js";
export { RouterHTTPClient } from "./router-client.js";
export { GatewayHTTPClient, fetchCatalog } from "./gateway-client.js";
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
  CallOptions,
  EnclaveOptions,
  RouterOptions,
  GatewayOptions,
  ModelPin,
  Catalog,
  CatalogEntry,
  ReplicaVerification,
} from "./options.js";
export { SDK_VERSION } from "./version.js";
