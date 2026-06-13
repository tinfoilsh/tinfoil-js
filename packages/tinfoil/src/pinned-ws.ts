import type * as WS from "ws";
import { createCheckServerIdentity } from "./pinned-tls-fetch.js";
import { ConfigurationError } from "./verifier.js";
import { isBun } from "./env.js";

/**
 * Options for creating a pinned WebSocket connection.
 */
export interface SecureWebSocketOptions {
  /** WebSocket subprotocols. */
  protocols?: string | string[];
  /**
   * Options forwarded to the `ws` client (e.g. headers for authentication).
   * TLS pinning options (`checkServerIdentity`, `rejectUnauthorized`) cannot
   * be overridden.
   */
  wsOptions?: WS.ClientOptions;
}

/**
 * Returns `ws` client options that pin the TLS connection to the attested
 * enclave public key. Standard certificate chain and hostname validation
 * still apply on top of the pin.
 */
export async function pinnedWsClientOptions(
  expectedFingerprintHex: string,
): Promise<WS.ClientOptions> {
  // Bun substitutes its own native implementation for the `ws` package, which
  // does not honor checkServerIdentity — the pin would be silently skipped.
  if (isBun()) {
    throw new ConfigurationError(
      "WebSocket TLS pinning is not supported on Bun: Bun replaces the 'ws' package " +
        "with a native implementation that does not honor checkServerIdentity.",
    );
  }

  const tls = await import("tls");
  const fingerprintCheck = createCheckServerIdentity(expectedFingerprintHex);

  // ws forwards checkServerIdentity verbatim to tls.connect, whose contract is
  // Error | undefined. @types/ws mistypes the return as boolean. Honoring this
  // would invert the check, so this cast here is necessary.
  const checkServerIdentity = (
    host: string,
    cert: import("tls").PeerCertificate,
  ): Error | undefined => {
    const result = fingerprintCheck(host, cert);
    if (result) return result;
    return tls.checkServerIdentity(host, cert);
  };

  return {
    rejectUnauthorized: true,
    checkServerIdentity: checkServerIdentity as unknown as NonNullable<
      WS.ClientOptions["checkServerIdentity"]
    >,
  };
}

/**
 * Opens a WebSocket to `url` with the TLS connection pinned to the attested
 * enclave public key. The returned socket is in the CONNECTING state; pinning
 * failures surface as an `error` event.
 */
export async function createPinnedWebSocket(
  url: string,
  expectedFingerprintHex: string,
  options?: SecureWebSocketOptions,
): Promise<WS.WebSocket> {
  const parsed = new URL(url);
  if (parsed.protocol !== "wss:") {
    throw new ConfigurationError(
      `Insecure connection rejected: only wss:// is allowed. Got ${url}`,
    );
  }

  const pinnedOptions = await pinnedWsClientOptions(expectedFingerprintHex);
  const { WebSocket } = await import("ws");
  return new WebSocket(parsed, options?.protocols, {
    ...options?.wsOptions,
    ...pinnedOptions,
  });
}
