import type * as WS from "ws";
import { createCheckServerIdentity } from "./pinned-tls-fetch.js";
import { ConfigurationError } from "./errors.js";
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
 * `ws` options that can bypass or weaken the pinned TLS identity check.
 */
const FORBIDDEN_WS_OPTION_KEYS = [
  "createConnection",
  "agent",
  "followRedirects",
  "session",
  "socket",
  "servername",
  "pskCallback",
] as const;

type HardenedWebSocketOptions = WS.ClientOptions & {
  session?: undefined;
  socket?: undefined;
  servername?: undefined;
  pskCallback?: undefined;
};

/**
 * Removes caller-supplied `ws` options that can bypass or weaken the TLS pin.
 */
export function stripUnsafeWebSocketOptions(
  wsOptions?: WS.ClientOptions,
): WS.ClientOptions | undefined {
  if (!wsOptions) return wsOptions;
  const sanitized: WS.ClientOptions = { ...wsOptions };
  for (const key of FORBIDDEN_WS_OPTION_KEYS) {
    delete (sanitized as Record<string, unknown>)[key];
  }
  return sanitized;
}

/**
 * Returns `ws` client options that pin the TLS connection to the attested
 * enclave public key. Standard certificate chain and hostname validation
 * still apply on top of the pin.
 */
export async function pinnedWsClientOptions(
  expectedFingerprintHex: string,
): Promise<WS.ClientOptions> {
  // Bun substitutes its own native implementation for the `ws` package. Before
  // Bun 1.4 it ignored checkServerIdentity, so the pin would be silently
  // skipped; 1.4+ calls it, but that path is not yet verified for pinning
  // (https://github.com/tinfoilsh/tinfoil-js/issues/224). Fail closed on all Bun.
  if (isBun()) {
    throw new ConfigurationError(
      "WebSocket TLS pinning is not supported on Bun: Bun replaces the 'ws' package " +
        "with a native implementation whose checkServerIdentity handling is not " +
        "verified for pinning (it is ignored before Bun 1.4).",
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

  const pinnedOptions: HardenedWebSocketOptions = {
    rejectUnauthorized: true,
    createConnection: undefined,
    agent: undefined,
    followRedirects: false,
    session: undefined,
    socket: undefined,
    servername: undefined,
    pskCallback: undefined,
    checkServerIdentity: checkServerIdentity as unknown as NonNullable<
      WS.ClientOptions["checkServerIdentity"]
    >,
  };
  return pinnedOptions;
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
    ...stripUnsafeWebSocketOptions(options?.wsOptions),
    ...pinnedOptions,
  });
}
