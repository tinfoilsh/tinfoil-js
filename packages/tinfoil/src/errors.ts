/**
 * The client's errors: one of three categories and the error that caused it.
 * A message reads as the category, a colon, then the cause, as in
 * "attestation error: <cause>". Errors from the OpenAI API keep their own
 * types.
 */

/** The categories a {@link TinfoilError} falls into. */
export type ErrorCategory = "configuration" | "network" | "attestation";

/** Base class for every error the client throws. */
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
 * verifier's `VerificationError` (from `@tinfoilsh/verifier`), whose `layer`
 * names the check that rejected it. A connection whose key doesn't match
 * the attested one, or a key the enclave no longer holds after rotation, is
 * reported as an AttestationError too.
 */
export class AttestationError extends TinfoilError {
  constructor(message: string, options?: { cause?: unknown }) {
    super("attestation", message, options);
    this.name = "AttestationError";
  }
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
