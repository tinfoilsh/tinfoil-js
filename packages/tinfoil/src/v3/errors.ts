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

/** Rejected evidence, policy, or channel binding: the enclave couldn't be trusted. */
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

/** `err` as a {@link NetworkError}, unless it is already a client error. */
export function wrapNetwork(err: unknown): TinfoilError {
  return err instanceof TinfoilError ? err : new NetworkError(messageOf(err), { cause: err });
}

/** `err` as an {@link AttestationError}, unless it is already a client error. */
export function wrapAttestation(err: unknown): TinfoilError {
  return err instanceof TinfoilError ? err : new AttestationError(messageOf(err), { cause: err });
}
