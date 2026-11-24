/**
 * The client's errors: one of three categories and the error that caused it.
 * A message reads as the category, a colon, then the cause, as in
 * "attestation error: <cause>". Errors from the OpenAI API keep their own
 * types.
 */

/**
 * The categories a {@link TinfoilError} falls into: the stable discriminant
 * to switch on, carried by every error's `category`.
 */
export type ErrorCategory = "configuration" | "network" | "attestation";

/**
 * Base class for every error the client throws. Switch on `category`, which
 * is the stable discriminant; `name` matches the concrete class
 * (`ConfigurationError`, `NetworkError` or `AttestationError`) for logs and
 * stack traces.
 */
export abstract class TinfoilError extends Error {
  readonly category: ErrorCategory;
  declare readonly cause?: unknown;

  constructor(category: ErrorCategory, message: string, options?: { cause?: unknown }) {
    super(`${category} error: ${message}`);
    this.category = category;
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/** How many links of a `cause` chain {@link findTinfoilError} follows before it gives up. */
const MAX_CAUSE_DEPTH = 32;

/**
 * The SDK error behind `err`: `err` itself when it is a {@link TinfoilError},
 * otherwise the first one in its `cause` chain, or undefined when there is
 * none. Use it on an error from an OpenAI client from `tinfoil/openai`: a
 * request whose attested transport fails, for example because the enclave
 * fails to verify again, rejects with the OpenAI library's
 * `APIConnectionError` (or `APIConnectionTimeoutError`), whose `cause` is the
 * SDK error.
 *
 * ```ts
 * try {
 *   await client.chat.completions.create(request);
 * } catch (err) {
 *   const sdk = findTinfoilError(err);
 *   if (sdk?.category === "attestation") stopUsing(client);
 *   else throw err;
 * }
 * ```
 *
 * The chain is followed at most 32 links, and a cycle in it ends the search.
 * An error from the API itself, such as `RateLimitError`, has no SDK error
 * behind it.
 */
export function findTinfoilError(err: unknown): TinfoilError | undefined {
  const seen = new Set<unknown>();
  let current = err;
  for (let depth = 0; depth <= MAX_CAUSE_DEPTH; depth++) {
    if (current instanceof TinfoilError) return current;
    if (typeof current !== "object" || current === null || seen.has(current)) return undefined;
    seen.add(current);
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

/** Invalid caller arguments or client configuration. Retrying won't help. */
export class ConfigurationError extends TinfoilError {
  constructor(message: string, options?: { cause?: unknown }) {
    super("configuration", message, options);
    this.name = "ConfigurationError";
  }
}

/**
 * The client couldn't reach what it needed: a network failure, a timeout or
 * an HTTP error status while fetching attestation material, or a gateway that
 * keeps routing a request away from its enclave.
 */
export class NetworkError extends TinfoilError {
  constructor(message: string, options?: { cause?: unknown }) {
    super("network", message, options);
    this.name = "NetworkError";
  }
}

/**
 * Rejected evidence, policy, or channel binding: the enclave couldn't be
 * trusted. When verification itself rejected the document, `cause` is the
 * verifier's `VerificationError` (which `tinfoil` re-exports), whose `layer`
 * names the check that rejected it and whose `report` shows the step that
 * failed and what the steps before it established. A connection whose key
 * doesn't match the attested one, or a key the enclave no longer holds after
 * rotation, is reported as an AttestationError too.
 */
export class AttestationError extends TinfoilError {
  constructor(message: string, options?: { cause?: unknown }) {
    super("attestation", message, options);
    this.name = "AttestationError";
  }
}

/**
 * How an unknown `kind` that untyped code passed is named in an error: a
 * string quoted, another primitive as written, and anything else by its
 * type, so that naming it can't throw.
 */
export function describeKind(kind: unknown): string {
  if (kind === undefined) return "a value without one";
  if (typeof kind === "string") return JSON.stringify(kind);
  if (typeof kind === "number" || typeof kind === "boolean" || typeof kind === "bigint" || kind === null) return String(kind);
  return `a ${typeof kind}`;
}

/** The message of an unknown thrown value. */
export function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The message of `err` without its category prefix: what it was constructed with. */
export function stripCategory(err: TinfoilError): string {
  const prefix = `${err.category} error: `;
  return err.message.startsWith(prefix) ? err.message.slice(prefix.length) : err.message;
}

/**
 * A plain error of `err`'s category with `message`, caused by what caused
 * `err` (or `err` itself): the form a layer throws when it gives up on
 * `err`, leaving behind any subclass and what that promised the caller.
 */
export function withMessage(err: TinfoilError, message: string): TinfoilError {
  const options = { cause: err.cause ?? err };
  if (err instanceof NetworkError) return new NetworkError(message, options);
  if (err instanceof ConfigurationError) return new ConfigurationError(message, options);
  return new AttestationError(message, options);
}

/** `err` as a {@link NetworkError}, unless it is already a client error. */
export function wrapNetwork(err: unknown): TinfoilError {
  return err instanceof TinfoilError ? err : new NetworkError(messageOf(err), { cause: err });
}

/** `err` as an {@link AttestationError}, unless it is already a client error. */
export function wrapAttestation(err: unknown): TinfoilError {
  return err instanceof TinfoilError ? err : new AttestationError(messageOf(err), { cause: err });
}
