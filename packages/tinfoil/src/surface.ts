/**
 * The package root's public surface, shared by its Node and browser entries:
 * the attested HTTP clients, their options, errors and helpers, the
 * pinned WebSockets, and the verifier's report types and error that the
 * clients return and throw. The OpenAI-compatible client lives in the
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
  OnVerificationAttempt,
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
/**
 * The verifier's report and the facts that it holds, which the clients
 * return, and the `VerificationError` that a rejection carries in its
 * `cause` chain. They are re-exported so that an app that names them
 * imports the copy of `@tinfoilsh/verifier` that this package pins: a direct
 * dependency on another version installs a second copy, whose
 * `VerificationError` fails `instanceof` on the errors that a client throws
 * and whose report types aren't the ones that a client returns.
 */
export { VerificationError, REPORT_SCHEMA_VERSION } from "@tinfoilsh/verifier";
export type {
  VerificationReport,
  VerifiedFacts,
  PartialFacts,
  ExpectedFacts,
  MeasuredFacts,
  CPUEvidence,
  Step,
  StepStatus,
  Layer,
  VerificationMetadata,
  ArtifactVerification,
  ConfigVerification,
  ReferenceSource,
  CryptoMaterialItem,
  Measurement,
  SevSnpMeasurement,
  TdxMeasurement,
  Expected,
  ExpectedSevSnp,
  ExpectedTdx,
  Register,
  VerificationReportJSON,
  VerifiedFactsJSON,
  PartialFactsJSON,
  ExpectedFactsJSON,
  MeasuredFactsJSON,
  StepJSON,
  VerificationMetadataJSON,
  ArtifactVerificationJSON,
  ConfigVerificationJSON,
  MeasurementJSON,
} from "@tinfoilsh/verifier";
