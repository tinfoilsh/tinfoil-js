/**
 * Realtime sessions in a browser: unavailable, since the connection can't be
 * pinned to the attested key there. This stub exists so bundlers resolve
 * the import.
 */
import type { OpenAIRealtimeWS } from "openai/realtime/ws";
import { ConfigurationError } from "./errors.js";
import type { EnclaveOpenAIClient, RouterOpenAIClient, TinfoilClient } from "./openai-client.js";
import type { RealtimeOptions } from "./options.js";
import { WEBSOCKETS_UNAVAILABLE_IN_BROWSERS } from "./internal/transport/ws.browser.js";

export async function createRealtimeWebSocket(_client: TinfoilClient | EnclaveOpenAIClient | RouterOpenAIClient, _options: RealtimeOptions): Promise<OpenAIRealtimeWS> {
  throw new ConfigurationError(WEBSOCKETS_UNAVAILABLE_IN_BROWSERS);
}
