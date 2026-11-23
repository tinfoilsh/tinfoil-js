/**
 * The package root's public surface, shared by its Node and browser entries:
 * the attested HTTP clients, their options, errors and helpers, and the
 * pinned WebSockets. The OpenAI-compatible client lives in the
 * `tinfoil/openai` entry and the AI SDK provider in `tinfoil/ai-sdk`, so
 * that the root imports no API library; platform-specific behaviour lives
 * behind the same client names.
 */
export { EnclaveHTTPClient } from "./enclave-client.js";
export { RouterHTTPClient } from "./router-client.js";
export { GatewayHTTPClient, fetchCatalog } from "./gateway-client.js";
export { TinfoilError, ConfigurationError, NetworkError, AttestationError, findTinfoilError, type ErrorCategory } from "./errors.js";
export {
  sessionRecoveryToken,
  serializeSessionRecoveryToken,
  deserializeSessionRecoveryToken,
  decryptResponseWithToken,
  type SessionRecoveryToken,
} from "./session-recovery.js";
export type {
  Fetch,
  AttestationFetcher,
  RouterListFetcher,
  Transport,
  TLS,
  EHBP,
  VerificationCheck,
  VerificationAttempt,
  OnVerification,
  CallOptions,
  EnclaveOptions,
  RouterOptions,
  GatewayOptions,
  ModelPin,
  Policy,
  ArtifactTrust,
  EndorsedArtifacts,
  EmbeddedArtifacts,
  Catalog,
  CatalogEntry,
  ReplicaVerification,
} from "./options.js";
export type { Trust, RepoPin, ProjectPin, SignedBy, AuthorizedBy, EmbeddedConfig, EitherPin } from "./trust.js";
export { SDK_VERSION } from "./version.js";
export { attestationRelay, routerListRelay, type RelayOptions } from "./fetchers.js";
export { createWebSocket, pinnedWebSocketOptions } from "./websocket.js";
export type { WebSocketOptions, PinnedWebSocket } from "./options.js";
