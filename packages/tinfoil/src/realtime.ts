/**
 * Realtime sessions over a pinned WebSocket. The OpenAI realtime client
 * builds its own `ws` WebSocket, so this module hands it settings that pin
 * the connection to the attested key and point it at the verified enclave,
 * whatever base URL the HTTP client's requests use. Node only: the browser
 * entry maps this module to a stub.
 */
import type { OpenAIRealtimeWS } from "openai/realtime/ws";
import { credentialOf } from "./internal/credential.js";
import { allowedWsOptions } from "./internal/transport/ws.js";
import { clientWsOptions, webSocketAccessOf } from "./internal/websocket.js";
import type { EnclaveOpenAIClient, RouterOpenAIClient, TinfoilClient } from "./openai-client.js";
import type { RealtimeOptions } from "./options.js";

/**
 * Opens a realtime session with the enclave `client` is verified against,
 * over a WebSocket pinned to the attested TLS key, authenticated with the
 * client's credential: its bearer token or API key, with an `apiKey`
 * function called for each session. Subscribe to the returned client's events; its
 * `socket` carries the connection lifecycle. A certificate failure in the
 * handshake makes the client verify again before its next connection. Node
 * only.
 */
export async function createRealtimeWebSocket(client: TinfoilClient | EnclaveOpenAIClient | RouterOpenAIClient, options: RealtimeOptions): Promise<OpenAIRealtimeWS> {
  const httpClient = client.httpClient;
  const { transport, tls } = webSocketAccessOf(httpClient);
  // A client no factory made is refused before any verification I/O.
  const resolveCredential = credentialOf(client);
  const pinned = await clientWsOptions(transport, tls, options.signal);
  const { OpenAIRealtimeWS } = await import("openai/realtime/ws");
  // The session goes to the enclave itself, not to a proxy the HTTP client may send through, with the
  // credential resolved here, so the realtime client takes the endpoint and key as plain values.
  const endpoint = { apiKey: await resolveCredential(), baseURL: `https://${httpClient.enclave}/v1/` };
  const session = new OpenAIRealtimeWS({ model: options.model, options: { ...allowedWsOptions(options.wsOptions), ...pinned.options } }, endpoint);
  session.socket.on("error", pinned.onConnectionError);
  return session;
}
