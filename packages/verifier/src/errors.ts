/** Invalid caller input or verifier configuration. */
export class UsageError extends Error {
  readonly cause?: unknown;
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "UsageError";
    this.cause = options?.cause;
  }
}
/** Evidence rejected at a verification boundary. Layer is extensible. */
export class VerificationError extends Error {
  readonly layer: string;
  readonly cause?: unknown;
  constructor(layer: string, message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "VerificationError";
    this.layer = layer;
    this.cause = options?.cause;
  }
}
/** @internal */
export async function atLayer<T>(
  layer: string,
  operation: () => Promise<T> | T,
): Promise<T> {
  try {
    return await operation();
  } catch (cause) {
    if (cause instanceof UsageError || cause instanceof VerificationError)
      throw cause;
    throw new VerificationError(
      layer,
      cause instanceof Error ? cause.message : `${layer} verification failed`,
      { cause },
    );
  }
}
