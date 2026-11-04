/**
 * What the platform allows of the transport modes. Node and Bun expose the
 * TLS connection, so both modes are available and TLS pinning is the
 * default; when the code finds itself in a browser anyway (a bundler that
 * ignored the browser build), it behaves as the browser build does.
 */
import { isRealBrowser } from "../../env.js";
import { ConfigurationError } from "../errors.js";
import type { TransportMode } from "../options.js";

/** Why the TLS mode is refused in a browser. */
export const TLS_UNAVAILABLE_IN_BROWSERS = 'the "tls" transport mode pins the server certificate, which browsers don\'t expose to scripts; use "ehbp", the browser default, which seals request and response bodies to the enclave\'s key instead';

export function defaultTransportMode(): TransportMode {
  return isRealBrowser() ? "ehbp" : "tls";
}

/** Rejects a mode the platform can't provide. */
export function checkTransportMode(mode: TransportMode): void {
  if (mode === "tls" && isRealBrowser()) throw new ConfigurationError(TLS_UNAVAILABLE_IN_BROWSERS);
}
