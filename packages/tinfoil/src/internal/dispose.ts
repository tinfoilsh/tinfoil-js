/// <reference lib="esnext.disposable" preserve="true" />
/**
 * What the HTTP clients' lifecycle shares: the symbol an `await using`
 * declaration disposes with, and the error a closed client answers with.
 * The lib reference above is kept in the published types, so
 * `Symbol.asyncDispose` and `AsyncDisposable` resolve for a consumer whose
 * own lib predates them.
 */
import { ConfigurationError } from "../errors.js";

/**
 * The well-known symbol `await using` disposes with. A runtime that predates
 * it has no such symbol, so its registry entry stands in; a client is then
 * still closed through `close()`.
 */
export const asyncDispose: typeof Symbol.asyncDispose = ((Symbol as { asyncDispose?: symbol }).asyncDispose ?? Symbol.for("Symbol.asyncDispose")) as typeof Symbol.asyncDispose;

/** The error a call on a closed client rejects with: using a client after closing it is a caller's mistake, not a network or attestation fault. */
export function closedError(): ConfigurationError {
  return new ConfigurationError("client is closed");
}
