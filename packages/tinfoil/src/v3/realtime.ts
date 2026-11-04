/**
 * Realtime sessions over a pinned WebSocket. The OpenAI realtime client
 * builds its own `ws` WebSocket, so this module hands it settings that pin
 * the connection to the attested key and point it at the verified enclave,
 * whatever base URL the HTTP client's requests use. Node only: the browser
 * entry maps this module to a stub.
 */
import type { OpenAIRealtimeWS } from "openai/realtime/ws";
import { allowedWsOptions } from "./internal/transport/ws.js";
import type { EnclaveOpenAIClient, RouterOpenAIClient, TinfoilClient } from "./openai-client.js";
import type { RealtimeOptions } from "./options.js";
import { pinnedWebSocketOptions } from "./websocket.js";

/**
 * Opens a realtime session with the enclave `client` is verified against,
 * over a WebSocket pinned to the attested TLS key, authenticated with the
 * client's credential. Subscribe to the returned client's events; its
 * `socket` carries the connection lifecycle. Node only.
 */
export async function createRealtimeWebSocket(client: TinfoilClient | EnclaveOpenAIClient | RouterOpenAIClient, options: RealtimeOptions): Promise<OpenAIRealtimeWS> {
  const httpClient = client.httpClient();
  const pinned = await pinnedWebSocketOptions(httpClient, options.signal);
  const { OpenAIRealtimeWS } = await import("openai/realtime/ws");
  // The session goes to the enclave itself, not to a proxy the HTTP client may send through.
  const endpoint = { apiKey: client.apiKey, baseURL: `https://${httpClient.enclave()}/v1/`, _callApiKey: client._callApiKey.bind(client) };
  return OpenAIRealtimeWS.create(endpoint, { model: options.model, options: { ...allowedWsOptions(options.wsOptions), ...pinned } });
}
