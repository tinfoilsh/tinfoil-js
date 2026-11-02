/**
 * Names the verification layer that rejected a document. More layers may be
 * added, so callers must tolerate values they do not recognize.
 */
export type Layer =
  /** The document can't be parsed, isn't bound to the nonce, or contradicts itself. */
  | "envelope"
  /** Reference values failed to authenticate or don't match the requested workload. */
  | "provenance"
  /** Hardware evidence isn't authentic. */
  | "quote"
  /** Authentic evidence doesn't satisfy the policy. */
  | "policy";

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

/**
 * Thrown by placeholder functions during the v3 port. The conformance adapter
 * maps it to "unsupported" so the suite skips instead of failing.
 * TODO(v3): delete once every placeholder is implemented.
 */
export class NotImplementedError extends Error {
  constructor(what: string) {
    super(`not implemented: ${what}`);
    this.name = "NotImplementedError";
  }
}
