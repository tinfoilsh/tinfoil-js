/**
 * Pinned WebSockets in a browser: unavailable, since a browser exposes
 * nothing of the TLS connection to pin. The clients refuse before reaching
 * this module; it exists so bundlers resolve the import.
 */
import type * as WS from "ws";
import { ConfigurationError } from "../../errors.js";
import type { PinnedWebSocket, WebSocketOptions } from "../../options.js";
import type { TLSOptions } from "./tls.js";

/** Which build this module belongs to; the browser build's bundling is checked against it. */
export const WS_PLATFORM: "node" | "browser" = "browser";

export const WEBSOCKETS_UNAVAILABLE_IN_BROWSERS = "a verified WebSocket pins the server certificate, which browsers don't expose to scripts, so it can't be opened from a browser";

export type OnRejected = () => void;

export function allowedWsOptions(wsOptions: Readonly<Record<string, unknown>> | undefined): Record<string, unknown> {
  return { ...wsOptions };
}

export function checkWsClientOptionsCapability(): void {
  throw new ConfigurationError(WEBSOCKETS_UNAVAILABLE_IN_BROWSERS);
}

export async function pinnedWsClientOptions(_key: string, _tls: TLSOptions, _onRejected?: OnRejected): Promise<WS.ClientOptions> {
  throw new ConfigurationError(WEBSOCKETS_UNAVAILABLE_IN_BROWSERS);
}

export async function openPinnedWebSocket(_url: URL, _key: string, _options: WebSocketOptions, _tls: TLSOptions, _onRejected?: OnRejected): Promise<PinnedWebSocket> {
  throw new ConfigurationError(WEBSOCKETS_UNAVAILABLE_IN_BROWSERS);
}
