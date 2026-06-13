/**
 * Browser stub for pinned-ws.
 * Browsers don't expose TLS certificate details, so a WebSocket connection
 * cannot be pinned to the attested enclave key. The runtime check in
 * secure-client.ts throws before reaching this code. This stub exists to
 * satisfy bundlers.
 */
/* eslint-disable @typescript-eslint/no-unused-vars */
import type * as WS from "ws";
import { ConfigurationError } from "./verifier.js";

export interface SecureWebSocketOptions {
  protocols?: string | string[];
  wsOptions?: WS.ClientOptions;
}

const BROWSER_ERROR =
  "Verified WebSockets are not supported in browser environments: browsers do not " +
  "expose TLS certificate details, so the connection cannot be pinned to the attested enclave key.";

export async function pinnedWsClientOptions(
  expectedFingerprintHex: string,
): Promise<WS.ClientOptions> {
  throw new ConfigurationError(BROWSER_ERROR);
}

export async function createPinnedWebSocket(
  url: string,
  expectedFingerprintHex: string,
  options?: SecureWebSocketOptions,
): Promise<WS.WebSocket> {
  throw new ConfigurationError(BROWSER_ERROR);
}
