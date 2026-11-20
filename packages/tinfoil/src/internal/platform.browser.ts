/**
 * What a browser allows of the transport modes: only EHBP, since a browser
 * exposes nothing of the TLS connection to pin. It is the default, and
 * selecting TLS is a configuration error.
 */
import { ConfigurationError } from "../errors.js";
import type { TransportMode } from "./transport/transport.js";

/** Which build this module belongs to; the browser build's bundling is checked against it. */
export const PLATFORM: "node" | "browser" = "browser";

/** Why the TLS mode is refused in a browser. */
export const TLS_UNAVAILABLE_IN_BROWSERS = 'the TLS transport ({ kind: "tls" }) pins the server certificate, which browsers don\'t expose to scripts; use the EHBP transport ({ kind: "ehbp" }), the browser default, which seals request and response bodies to the enclave\'s key instead';

/** The globals a runtime identifies itself by; unused in the browser build, where nothing is a server. */
export interface RuntimeGlobals {
  readonly process?: { readonly versions?: { readonly node?: string; readonly bun?: string } };
  readonly Bun?: unknown;
  readonly Deno?: { readonly version?: { readonly deno?: string } };
}

/** Never a server in the browser build: the secret stays in memory and the transport default is EHBP. */
export function isServerRuntime(_globals: RuntimeGlobals = globalThis as RuntimeGlobals): boolean {
  return false;
}

/** Never Deno in the browser build. */
export function checkDenoPins(_globals: RuntimeGlobals = globalThis as RuntimeGlobals): void {}

/** Never Bun in the browser build; the transports that tell Bun from Node are mapped to stubs here. */
export function isBun(_globals: RuntimeGlobals = globalThis as RuntimeGlobals): boolean {
  return false;
}

export function defaultTransportMode(): TransportMode {
  return "ehbp";
}

/** Rejects a mode the platform can't provide. */
export function checkTransportMode(mode: TransportMode): void {
  if (mode === "tls") throw new ConfigurationError(TLS_UNAVAILABLE_IN_BROWSERS);
}
