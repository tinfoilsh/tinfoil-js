/**
 * Realtime sessions in a browser: unavailable, since the connection can't be
 * pinned to the attested key there. This stub exists so bundlers resolve
 * the import.
 */
import type { OpenAIRealtimeWS } from "openai/realtime/ws";
import { ConfigurationError } from "./errors.js";
import type { EnclaveHTTPClient } from "./enclave-client.js";
import type { OpenAIClient } from "./openai-client.js";
import type { RealtimeOptions } from "./options.js";
import type { RouterHTTPClient } from "./router-client.js";
import { WEBSOCKETS_UNAVAILABLE_IN_BROWSERS } from "./internal/transport/ws.browser.js";

export async function createRealtimeWebSocket(_client: OpenAIClient<EnclaveHTTPClient | RouterHTTPClient>, _options: RealtimeOptions): Promise<OpenAIRealtimeWS> {
  throw new ConfigurationError(WEBSOCKETS_UNAVAILABLE_IN_BROWSERS);
}
