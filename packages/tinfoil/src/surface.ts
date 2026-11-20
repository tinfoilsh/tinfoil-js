/**
 * The package root's public surface, shared by its Node and browser entries:
 * the attested HTTP clients, which the `tinfoil/http` entry exposes through
 * `./http.js`, and the pinned WebSockets. The OpenAI-compatible client lives
 * in the `tinfoil/openai` entry, so that the root imports no API library;
 * platform-specific behaviour lives behind the same client names.
 */
export * from "./http.js";
export { createWebSocket, pinnedWebSocketOptions } from "./websocket.js";
export type { WebSocketOptions, PinnedWebSocket } from "./options.js";
