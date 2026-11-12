/**
 * The package root's public surface, shared by its Node and browser entries.
 * The `tinfoil/http` entry exposes the HTTP subset through `./http.js`;
 * platform-specific behaviour lives behind the same client names.
 */
export * from "./http.js";
export { TinfoilClient, createClient, EnclaveOpenAIClient, RouterOpenAIClient, GatewayOpenAIClient, type OpenAIOptions } from "./openai-client.js";
export { createWebSocket, pinnedWebSocketOptions } from "./websocket.js";
export { createRealtimeWebSocket } from "./realtime.js";
export type { WebSocketOptions, PinnedWebSocket, RealtimeOptions } from "./options.js";

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
