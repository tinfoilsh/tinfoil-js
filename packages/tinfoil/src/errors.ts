/** Client errors classify what an application can do, without verifier layers. */
export class TinfoilError extends Error {
  readonly cause?: unknown;
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = new.target.name;
    this.cause = options?.cause;
  }
}
export class ConfigurationError extends TinfoilError {}
export class AttestationError extends TinfoilError {}
export class NetworkError extends TinfoilError {}

// Private recovery authority: an arbitrary AttestationError is not a rotation signal.
const rejectedBindings = new WeakSet<object>();
export function bindingError(message: string, cause?: unknown): AttestationError {
  const error = new AttestationError(message, { cause });
  rejectedBindings.add(error);
  return error;
}
export function isBindingRejection(error: unknown): boolean {
  return typeof error === "object" && error !== null && rejectedBindings.has(error);
}
/** Preserve the terminal action category while retaining the earlier recovery signal. */
export function recoveryFailure(error: unknown, previous: unknown): unknown {
  const cause = { primary: error, previous };
  if (error instanceof ConfigurationError) return new ConfigurationError(error.message, { cause });
  if (error instanceof AttestationError) return new AttestationError(error.message, { cause });
  if (error instanceof NetworkError) return new NetworkError(error.message, { cause });
  return error;
}
