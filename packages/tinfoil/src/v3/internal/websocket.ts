/**
 * WebSockets from a client to its verified enclave. A WebSocket can't be
 * sealed the way an HTTP body can, so it always goes directly to the enclave
 * over a connection pinned to the TLS key of the client's current
 * verification, whatever transport mode the client's requests use, and only
 * on a runtime that exposes the connection (Node and Bun). A pin failure
 * invalidates the verification the connection was opened under, so the
 * next call verifies again.
 */
import type * as WS from "ws";
import { AttestationError, ConfigurationError } from "../errors.js";
import type { PinnedWebSocket, WebSocketOptions } from "../options.js";
import { isServerRuntime, type RuntimeGlobals } from "./platform.js";
import { normalizedOrigin } from "./transport/origin.js";
import { isCertificateError } from "./transport/pin.js";
import type { TLSOptions } from "./transport/tls.js";
import type { KeyedTransport } from "./transport/transport.js";

export const WEBSOCKETS_UNAVAILABLE_IN_BROWSERS = "a verified WebSocket pins the server certificate, which browsers don't expose to scripts, so it can't be opened from a browser";

/** What a WebSocket needs from a client: its transport (verification cache and enclave) and its TLS settings. */
export interface WebSocketAccess {
  readonly transport: KeyedTransport;
  readonly tls: TLSOptions;
}

const access = new WeakMap<object, WebSocketAccess>();

/** Records, for a client its factory constructed, what a WebSocket to its enclave needs. */
export function registerWebSocketAccess(client: object, transport: KeyedTransport, tls: TLSOptions): void {
  access.set(client, { transport, tls });
}

/** The access a factory registered for `client`; anything else is refused. */
export function webSocketAccessOf(client: object): WebSocketAccess {
  const found = access.get(client);
  if (found === undefined) throw new ConfigurationError("client was not created by its factory");
  return found;
}

/** Rejects a runtime that can't pin a connection. */
export function checkWebSocketCapability(globals: RuntimeGlobals = globalThis as RuntimeGlobals): void {
  if (!isServerRuntime(globals)) throw new ConfigurationError(WEBSOCKETS_UNAVAILABLE_IN_BROWSERS);
}

/**
 * The `wss://` URL for `path` on the enclave: a path (and query) relative to
 * the enclave's origin, or an absolute `https://` or `wss://` URL on that
 * origin. Any other scheme or host is refused, since the handshake's
 * headers would otherwise travel to whatever the URL names.
 */
export function webSocketURL(host: string, path: string): URL {
  let target: URL;
  try {
    target = new URL(path, `https://${host}/`);
  } catch {
    throw new ConfigurationError(`WebSocket path is not a valid URL: ${JSON.stringify(path)}`);
  }
  if (target.protocol === "https:") target.protocol = "wss:";
  if (target.protocol !== "wss:") throw new ConfigurationError(`a verified WebSocket requires wss://, got ${JSON.stringify(target.toString())}`);
  const enclaveOrigin = normalizedOrigin(new URL(`wss://${host}`));
  if (normalizedOrigin(target) !== enclaveOrigin) {
    throw new ConfigurationError(`refusing WebSocket connection to ${JSON.stringify(target.host)}: client is bound to enclave ${JSON.stringify(host)}`);
  }
  return target;
}

/** Opens a WebSocket from the client whose transport is `transport` to `path` on its enclave. */
export async function openClientWebSocket(transport: KeyedTransport, path: string, options: WebSocketOptions, tls: TLSOptions): Promise<PinnedWebSocket> {
  checkWebSocketCapability();
  const target = webSocketURL(transport.enclave().host(), path);
  const state = await transport.state(options.signal);
  const key = state.verification.tlsPublicKeyFP();
  if (key === undefined) throw new AttestationError('document endorses no "tls" key');
  const { openPinnedWebSocket } = await import("./transport/ws.js");
  const socket = await openPinnedWebSocket(target, key, options, tls);
  // A connection the peer's certificate failed was opened under keys the peer no longer holds.
  socket.addEventListener("error", (event) => {
    if (isCertificateError(event.error)) transport.invalidate(state);
  });
  return socket;
}

/** `ws` client settings pinning a connection to the client's current verification, for libraries that build their own WebSocket. */
export async function clientWsOptions(transport: KeyedTransport, tls: TLSOptions, signal?: AbortSignal): Promise<WS.ClientOptions> {
  checkWebSocketCapability();
  const key = (await transport.ensureVerified(signal)).tlsPublicKeyFP();
  if (key === undefined) throw new AttestationError('document endorses no "tls" key');
  const { pinnedWsClientOptions } = await import("./transport/ws.js");
  return pinnedWsClientOptions(key, tls);
}
