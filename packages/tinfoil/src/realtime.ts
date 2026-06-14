import type * as WS from "ws";
import type { OpenAIRealtimeWS } from "openai/realtime/ws";
import { stripUnsafeWebSocketOptions } from "./pinned-ws.js";

/**
 * Constructs an OpenAI realtime WebSocket client with TLS pinning injected.
 * `openai/realtime/ws` imports the `ws` package, so this module is Node-only
 * and loaded dynamically (with a browser stub mapped in package.json).
 */
export async function createPinnedRealtimeWS(
  props: { model: string; options?: WS.ClientOptions },
  client: { apiKey: string; baseURL: string },
  pinnedOptions: WS.ClientOptions,
): Promise<OpenAIRealtimeWS> {
  const { OpenAIRealtimeWS } = await import("openai/realtime/ws");
  return new OpenAIRealtimeWS(
    {
      model: props.model,
      options: { ...stripUnsafeWebSocketOptions(props.options), ...pinnedOptions },
    },
    client,
  );
}
