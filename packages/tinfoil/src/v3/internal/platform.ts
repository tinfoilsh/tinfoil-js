/**
 * What the platform allows of the transport modes. Node and Bun expose the
 * TLS connection, so both modes are available and TLS pinning is the
 * default. Anywhere else, a browser page or a worker reached by a bundler
 * that ignored the browser build, this module behaves as the browser build
 * does: a runtime is a server only when it says so.
 */
import { ConfigurationError } from "../errors.js";
import type { TransportMode } from "../options.js";

/** Which build this module belongs to; the browser build's bundling is checked against it. */
export const PLATFORM: "node" | "browser" = "node";

/** Why the TLS mode is refused in a browser. */
export const TLS_UNAVAILABLE_IN_BROWSERS = 'the "tls" transport mode pins the server certificate, which browsers don\'t expose to scripts; use "ehbp", the browser default, which seals request and response bodies to the enclave\'s key instead';

/** The globals a runtime identifies itself by. */
export interface RuntimeGlobals {
  readonly process?: { readonly versions?: { readonly node?: string; readonly bun?: string } };
  readonly Bun?: unknown;
}

/** Whether `globals` belong to Node or Bun, the runtimes that expose the TLS connection; anything else is treated as a browser. */
export function isServerRuntime(globals: RuntimeGlobals = globalThis as RuntimeGlobals): boolean {
  const versions = globals.process?.versions;
  return Boolean(versions?.node) || Boolean(versions?.bun) || globals.Bun !== undefined;
}

export function defaultTransportMode(globals: RuntimeGlobals = globalThis as RuntimeGlobals): TransportMode {
  return isServerRuntime(globals) ? "tls" : "ehbp";
}

/** Rejects a mode the platform can't provide. */
export function checkTransportMode(mode: TransportMode, globals: RuntimeGlobals = globalThis as RuntimeGlobals): void {
  if (mode === "tls" && !isServerRuntime(globals)) throw new ConfigurationError(TLS_UNAVAILABLE_IN_BROWSERS);
}
