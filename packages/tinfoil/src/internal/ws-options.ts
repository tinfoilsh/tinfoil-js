/**
 * Checks the `ws` client settings that a caller passes as `wsOptions`. The
 * settings that a pinned connection owns are refused rather than dropped, so
 * that code without types, which the {@link WsOptions} type can't stop,
 * learns that a setting it relies on (an `Authorization` header in
 * `wsOptions.headers`, say) would not be sent. Shared by every build, so
 * that each refuses the same settings in the same words.
 */
import { ConfigurationError } from "../errors.js";
import type { ReservedWsOption, WsOptions } from "../options.js";
import { isBun, type RuntimeGlobals } from "./platform.js";

/** The call that the settings were passed to, which decides what a refusal suggests instead. */
export type WsOptionsCaller = "createWebSocket" | "createRealtimeWebSocket";

const PINNED = "the SDK sets it so that the connection is pinned to the attested key";

/**
 * Why each reserved setting is refused, and what to use instead. The record
 * keeps the list and the {@link ReservedWsOption} type in step: a key that
 * is missing from either fails to compile.
 */
const RESERVED_WS_OPTIONS = {
  agent: () => PINNED,
  createConnection: () => PINNED,
  followRedirects: () => PINNED,
  session: () => PINNED,
  socket: () => PINNED,
  servername: () => PINNED,
  pskCallback: () => PINNED,
  checkServerIdentity: () => PINNED,
  rejectUnauthorized: () => PINNED,
  ca: () => PINNED,
  finishRequest: () => "it would hand over the handshake request, whose headers the SDK sets",
  headers: (caller) =>
    caller === "createWebSocket"
      ? "pass the handshake's headers in the top-level `headers` option instead"
      : "createRealtimeWebSocket sends no headers of the caller's; it authenticates with the client's credential",
  origin: (caller) =>
    caller === "createWebSocket"
      ? "set an `Origin` header in the top-level `headers` option instead"
      : "createRealtimeWebSocket sends no headers of the caller's, `Origin` included",
  protocol: (caller) =>
    caller === "createWebSocket"
      ? "it is the request's URL scheme, which the URL sets; offer subprotocols with the top-level `protocols` option instead"
      : "it is the request's URL scheme, which the URL sets",
} satisfies Record<ReservedWsOption, (caller: WsOptionsCaller) => string>;

export const WS_OPTIONS_REFUSED_ON_BUN = "Bun's WebSocket takes no `ws` client settings, so `wsOptions` must be empty on Bun";

/**
 * A copy of `wsOptions` for the `ws` client, after refusing, before any I/O,
 * a setting that a pinned connection owns: one of the reserved keys as an
 * own property whose value is not `undefined`. For `createWebSocket` on Bun,
 * whose WebSocket takes none of these settings, any setting is refused
 * (`createRealtimeWebSocket` is refused on Bun altogether). The value is
 * typed loosely because code without types can pass anything.
 */
export function checkedWsOptions(
  wsOptions: WsOptions | Readonly<Record<string, unknown>> | undefined,
  caller: WsOptionsCaller,
  globals: RuntimeGlobals = globalThis as RuntimeGlobals,
): Record<string, unknown> {
  if (wsOptions === undefined || wsOptions === null) return {};
  if (typeof wsOptions !== "object") throw new ConfigurationError(`wsOptions must be an object, got ${typeof wsOptions}`);
  const options = wsOptions as Readonly<Record<string, unknown>>;
  for (const [key, why] of Object.entries(RESERVED_WS_OPTIONS)) {
    if (Object.prototype.hasOwnProperty.call(options, key) && options[key] !== undefined) {
      throw new ConfigurationError(`wsOptions.${key} is reserved: ${why(caller)}`);
    }
  }
  if (caller === "createWebSocket" && isBun(globals) && Object.keys(options).some((key) => options[key] !== undefined)) throw new ConfigurationError(WS_OPTIONS_REFUSED_ON_BUN);
  return { ...options };
}
