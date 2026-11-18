/**
 * What the platform allows of the transport modes. Node and Bun expose the
 * TLS connection, so both modes are available and TLS pinning is the
 * default; a Bun too old to check a connection before it sends over it
 * gets the browser default. Anywhere else, a browser page or a worker
 * reached by a bundler that ignored the browser build, this module behaves
 * as the browser build does: a runtime is a server only when it says so.
 */
import { ConfigurationError } from "../errors.js";
import type { TransportMode } from "../options.js";

/** Which build this module belongs to; the browser build's bundling is checked against it. */
export const PLATFORM: "node" | "browser" = "node";

/** Why the TLS mode is refused in a browser. */
export const TLS_UNAVAILABLE_IN_BROWSERS = 'the "tls" transport mode pins the server certificate, which browsers don\'t expose to scripts; use "ehbp", the browser default, which seals request and response bodies to the enclave\'s key instead';

/**
 * The oldest Bun whose fetch runs a caller's certificate check before it
 * writes the request. An older one writes the request first and runs the
 * check once the response arrives, so a peer without the attested key would
 * receive the request in full.
 */
export const MIN_BUN_FOR_TLS_MODE = "1.4.0";

/**
 * The oldest Bun whose WebSocket runs a caller's certificate check at all.
 * An older one opens the connection, upgrade request and all, whatever the
 * check would have said.
 */
export const MIN_BUN_FOR_PINNED_WEBSOCKETS = "1.4.4";

/**
 * The oldest Deno whose `node:https` and `ws` both run a caller's
 * certificate check. Through 2.7.0 `node:https` never calls it, so a peer
 * without the attested key would receive the request; 2.7.14 runs it for
 * `node:https` and crashes on a rejected `ws` connection.
 */
export const MIN_DENO_FOR_TLS_MODE = "2.8.0";

/** Why the TLS mode and a pinned WebSocket are refused on a Deno older than {@link MIN_DENO_FOR_TLS_MODE}. */
export function pinningUnavailableOnDeno(version: string): string {
  return `pinning the server certificate needs Deno ${MIN_DENO_FOR_TLS_MODE} or later: Deno ${version} connects without running the caller's certificate check; for requests, the "ehbp" transport mode seals request and response bodies to the enclave's key instead`;
}

/** Why the TLS mode is refused on a Bun older than {@link MIN_BUN_FOR_TLS_MODE}. */
export function tlsUnavailableOnBun(version: string): string {
  return `the "tls" transport mode pins the server certificate, which Bun ${version} checks only after sending the request; use Bun ${MIN_BUN_FOR_TLS_MODE} or later, or "ehbp", which seals request and response bodies to the enclave's key instead`;
}

/** Why a pinned WebSocket is refused on a Bun older than {@link MIN_BUN_FOR_PINNED_WEBSOCKETS}. */
export function webSocketsUnavailableOnBun(version: string): string {
  return `a pinned WebSocket needs Bun ${MIN_BUN_FOR_PINNED_WEBSOCKETS} or later: Bun ${version} opens a WebSocket without running the caller's certificate check`;
}

/** The globals a runtime identifies itself by. */
export interface RuntimeGlobals {
  readonly process?: { readonly versions?: { readonly node?: string; readonly bun?: string } };
  readonly Bun?: unknown;
  readonly Deno?: { readonly version?: { readonly deno?: string } };
}

/** Whether `globals` belong to Node or Bun, the runtimes that expose the TLS connection; anything else is treated as a browser. */
export function isServerRuntime(globals: RuntimeGlobals = globalThis as RuntimeGlobals): boolean {
  const versions = globals.process?.versions;
  return Boolean(versions?.node) || Boolean(versions?.bun) || globals.Bun !== undefined;
}

/** Whether `globals` belong to Bun, which pins TLS connections through its own fetch and WebSocket rather than Node's. */
export function isBun(globals: RuntimeGlobals = globalThis as RuntimeGlobals): boolean {
  return Boolean(globals.process?.versions?.bun);
}

/**
 * The version of the Bun that `globals` describe when it is older than
 * `floor`; undefined on a Bun at least that new, and on any other runtime.
 * Versions compare as major.minor.patch; what follows the patch (a canary
 * tag) is ignored, and a version that doesn't parse as three numbers
 * counts as older.
 */
export function bunOlderThan(floor: string, globals: RuntimeGlobals = globalThis as RuntimeGlobals): string | undefined {
  return olderThan(globals.process?.versions?.bun, floor);
}

/** {@link bunOlderThan} for the Deno that `globals` describe. */
export function denoOlderThan(floor: string, globals: RuntimeGlobals = globalThis as RuntimeGlobals): string | undefined {
  return olderThan(globals.Deno?.version?.deno, floor);
}

function olderThan(version: string | undefined, floor: string): string | undefined {
  if (version === undefined || version === "") return undefined;
  const have = parseVersion(version);
  if (have === undefined) return version;
  const want = parseVersion(floor);
  if (want === undefined) throw new Error(`not a version: ${JSON.stringify(floor)}`);
  for (let i = 0; i < 3; i++) {
    if (have[i] !== want[i]) return have[i]! < want[i]! ? version : undefined;
  }
  return undefined;
}

/** The major, minor and patch of `v`, or undefined unless each is a decimal number; a tag after the patch is ignored. */
function parseVersion(v: string): readonly [number, number, number] | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(v);
  return match === null ? undefined : [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** TLS pinning where the runtime checks a connection before it sends over it (Node, Bun from {@link MIN_BUN_FOR_TLS_MODE}, Deno from {@link MIN_DENO_FOR_TLS_MODE}); EHBP anywhere else. */
export function defaultTransportMode(globals: RuntimeGlobals = globalThis as RuntimeGlobals): TransportMode {
  const pins = bunOlderThan(MIN_BUN_FOR_TLS_MODE, globals) === undefined && denoOlderThan(MIN_DENO_FOR_TLS_MODE, globals) === undefined;
  return isServerRuntime(globals) && pins ? "tls" : "ehbp";
}

/** Rejects a mode the platform can't provide. */
export function checkTransportMode(mode: TransportMode, globals: RuntimeGlobals = globalThis as RuntimeGlobals): void {
  if (mode !== "tls") return;
  if (!isServerRuntime(globals)) throw new ConfigurationError(TLS_UNAVAILABLE_IN_BROWSERS);
  const old = bunOlderThan(MIN_BUN_FOR_TLS_MODE, globals);
  if (old !== undefined) throw new ConfigurationError(tlsUnavailableOnBun(old));
  checkDenoPins(globals);
}

/** Rejects a Deno older than {@link MIN_DENO_FOR_TLS_MODE}, which pins no connection. */
export function checkDenoPins(globals: RuntimeGlobals = globalThis as RuntimeGlobals): void {
  const old = denoOlderThan(MIN_DENO_FOR_TLS_MODE, globals);
  if (old !== undefined) throw new ConfigurationError(pinningUnavailableOnDeno(old));
}
