/**
 * What a browser allows of the transport modes: only EHBP, since a browser
 * exposes nothing of the TLS connection to pin. It is the default, and
 * selecting TLS is a configuration error.
 */
import { ConfigurationError } from "../errors.js";
import type { TransportMode } from "../options.js";

/** Which build this module belongs to; the browser build's bundling is checked against it. */
export const PLATFORM: "node" | "browser" = "browser";

/** Why the TLS mode is refused in a browser. */
export const TLS_UNAVAILABLE_IN_BROWSERS = 'the "tls" transport mode pins the server certificate, which browsers don\'t expose to scripts; use "ehbp", the browser default, which seals request and response bodies to the enclave\'s key instead';

export function defaultTransportMode(): TransportMode {
  return "ehbp";
}

/** Rejects a mode the platform can't provide. */
export function checkTransportMode(mode: TransportMode): void {
  if (mode === "tls") throw new ConfigurationError(TLS_UNAVAILABLE_IN_BROWSERS);
}
