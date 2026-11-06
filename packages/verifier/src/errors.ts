/** The verification layers today, in the order a document passes through them. */
export type KnownLayer =
  /** The document can't be parsed, isn't bound to the nonce, or contradicts itself. */
  | "envelope"
  /** Reference values failed to authenticate or don't match the requested workload. */
  | "provenance"
  /** Hardware evidence isn't authentic. */
  | "quote"
  /** Authentic evidence doesn't satisfy the policy. */
  | "policy";

/**
 * Names the verification layer that rejected a document: one of the
 * {@link KnownLayer} values today, and a later version may add more. The
 * type is open so a caller compiles against the names it knows; a value it
 * doesn't recognize is still a rejection, at a stage it has no name for,
 * and must be treated as one.
 */
export type Layer = KnownLayer | (string & {});

/** Base class for every error this package throws. */
export abstract class VerifyError extends Error {
  declare readonly cause?: unknown;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/** The verifier was built or called with invalid inputs. Retrying won't help. */
export class UsageError extends VerifyError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(`usage error: ${message}`, options);
    this.name = "UsageError";
  }
}

/** A document that must not be trusted, and the layer that rejected it. */
export class VerificationError extends VerifyError {
  readonly layer: Layer;

  constructor(layer: Layer, message: string, options?: { cause?: unknown }) {
    super(`verification error: ${layer}: ${message}`, options);
    this.name = "VerificationError";
    this.layer = layer;
  }
}
