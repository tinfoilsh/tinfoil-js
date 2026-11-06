/**
 * WebSockets to the enclave a client is verified against. A WebSocket can't
 * be sealed the way an HTTP body can, so it goes directly to the enclave
 * over a connection pinned to the TLS key of the client's current
 * verification, whatever transport mode the client's requests use.
 */
import type * as WS from "ws";
import type { EnclaveHTTPClient } from "./enclave-client.js";
import { clientWsOptions, openClientWebSocket, webSocketAccessOf } from "./internal/websocket.js";
import type { CallOptions, PinnedWebSocket, WebSocketOptions } from "./options.js";
import type { RouterHTTPClient } from "./router-client.js";

/**
 * Opens a WebSocket to `path` on `client`'s enclave (a path and query such
 * as `/v1/realtime?model=…`, or a URL on the enclave's origin) over a
 * connection pinned to the attested TLS key. The client verifies first if
 * its verification has expired. Node and Bun only; a browser is a
 * {@link ConfigurationError}. The socket is returned in the CONNECTING
 * state; a pin failure surfaces as its `error` event and makes the next call
 * verify again.
 */
export async function createWebSocket(client: EnclaveHTTPClient | RouterHTTPClient, path: string, options?: WebSocketOptions): Promise<PinnedWebSocket> {
  const { transport, tls } = webSocketAccessOf(client);
  return openClientWebSocket(transport, path, options ?? {}, tls);
}

/**
 * `ws` client settings that pin a connection to the attested TLS key of
 * `client`'s current verification, for a library that builds its own
 * WebSocket to the enclave. Node only. A peer whose certificate fails the
 * pin fails the handshake and makes the client verify again before its next
 * connection; a certificate the runtime rejects before the pin is consulted
 * surfaces as the runtime's error on the library's socket and leaves the
 * verification in place.
 */
export async function pinnedWebSocketOptions(client: EnclaveHTTPClient | RouterHTTPClient, options?: CallOptions): Promise<WS.ClientOptions> {
  const { transport, tls } = webSocketAccessOf(client);
  return (await clientWsOptions(transport, tls, options?.signal)).options;
}
