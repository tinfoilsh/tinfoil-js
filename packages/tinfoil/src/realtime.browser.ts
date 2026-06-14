/**
 * Browser stub for realtime.
 * Verified realtime connections require TLS pinning, which browsers cannot do.
 * The runtime check in secure-client.ts throws before reaching this code.
 * This stub exists to satisfy bundlers.
 */
import type * as WS from "ws";
import type { OpenAIRealtimeWS } from "openai/realtime/ws";
import { ConfigurationError } from "./verifier.js";

export async function createPinnedRealtimeWS(
  _props: { model: string; options?: WS.ClientOptions },
  _client: { apiKey: string; baseURL: string },
  _pinnedOptions: WS.ClientOptions,
): Promise<OpenAIRealtimeWS> {
  throw new ConfigurationError(
    "Verified realtime connections are not supported in browser environments: browsers do not " +
      "expose TLS certificate details, so the connection cannot be pinned to the attested enclave key.",
  );
}
