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

/**
 * The key under which every error of this package carries its brand: its
 * class name, stamped by the constructor. The key is registered globally, so
 * two copies of the package loaded side by side (two versions installed, or
 * a bundle that failed to dedupe) share it, and `instanceof` against one
 * copy's classes recognizes the other copy's errors.
 */
const BRAND = Symbol.for("@tinfoilsh/verifier.error");

/** The brands the two concrete error classes stamp. */
type Brand = "UsageError" | "VerificationError";

/** The brand `value` carries, or undefined for anything this package didn't construct. */
function brandOf(value: unknown): Brand | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const brand = (value as { [BRAND]?: unknown })[BRAND];
  return brand === "UsageError" || brand === "VerificationError" ? brand : undefined;
}

/** Stamps `err` with its brand, as a non-enumerable property so serializing or logging the error doesn't show it. */
function stamp(err: VerifyError, brand: Brand): void {
  Object.defineProperty(err, BRAND, { value: brand, enumerable: false, writable: false, configurable: false });
}

/** Whether `value` is an instance of `cls` by its prototype chain: the usual `instanceof`, which a subclass defined outside this package relies on. */
const byPrototype = (cls: abstract new (...args: never[]) => unknown, value: unknown): boolean => Function.prototype[Symbol.hasInstance].call(cls, value);

/**
 * Base class for every error this package throws. `instanceof` holds for
 * an error from another loaded copy of the package too: each error carries
 * a brand under a globally registered key, which the three classes of this
 * module check after the prototype chain. `Symbol.hasInstance` is
 * inherited, so each check applies only when `this` is that class itself;
 * a subclass defined elsewhere matches by its prototype chain alone.
 */
export abstract class VerifyError extends Error {
  declare readonly cause?: unknown;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }

  static [Symbol.hasInstance](value: unknown): boolean {
    return byPrototype(this, value) || (this === VerifyError && brandOf(value) !== undefined);
  }
}

/** The verifier was built or called with invalid inputs. Retrying won't help. */
export class UsageError extends VerifyError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(`usage error: ${message}`, options);
    this.name = "UsageError";
    stamp(this, "UsageError");
  }

  static override [Symbol.hasInstance](value: unknown): boolean {
    return byPrototype(this, value) || (this === UsageError && brandOf(value) === "UsageError");
  }
}

/**
 * A document that must not be trusted, and the layer that rejected it. The
 * verifier fails closed: a failure inside a layer that is not itself a
 * VerifyError, such as a bug or an exhausted resource, is reported as a
 * rejection at that layer with the underlying error as `cause`. An
 * unfamiliar message at a layer may therefore be the verifier failing
 * rather than the document, and `cause` says which.
 */
export class VerificationError extends VerifyError {
  readonly layer: Layer;

  constructor(layer: Layer, message: string, options?: { cause?: unknown }) {
    super(`verification error: ${layer}: ${message}`, options);
    this.name = "VerificationError";
    this.layer = layer;
    stamp(this, "VerificationError");
  }

  static override [Symbol.hasInstance](value: unknown): boolean {
    return byPrototype(this, value) || (this === VerificationError && brandOf(value) === "VerificationError");
  }
}
