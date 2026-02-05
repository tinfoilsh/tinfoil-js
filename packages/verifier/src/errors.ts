/**
 * Error classes for the Tinfoil SDK.
 * 
 * Hierarchy:
 * ```
 * TinfoilError (base)
 * ├── ConfigurationError   - Client misconfigured or used incorrectly
 * ├── FetchError           - Couldn't fetch attestation materials
 * └── AttestationError     - Attestation failed (security issue)
 * ```
 */

/**
 * Base error class for all Tinfoil SDK errors.
 */
export class TinfoilError extends Error {
  constructor(message: string, options?: { cause?: Error }) {
    super(message);
    this.name = 'TinfoilError';
    if (options?.cause) {
      this.cause = options.cause;
    }
  }
}

/**
 * Thrown when the client is misconfigured or used incorrectly.
 * 
 * Examples:
 * - Missing required options (serverURL, configRepo, apiKey)
 * - Invalid option values
 * - Calling methods before client is ready
 * - Using the wrong client type
 * 
 * Action: Fix your code
 */
export class ConfigurationError extends TinfoilError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, options);
    this.name = 'ConfigurationError';
  }
}

/**
 * Thrown when fetching attestation materials fails.
 * 
 * Examples:
 * - Network unreachable
 * - HTTP errors (404, 500, etc.)
 * - Invalid response format (bad JSON, wrong schema)
 * - Timeout
 * 
 * Action: Retry, check network connectivity
 */
export class FetchError extends TinfoilError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, options);
    this.name = 'FetchError';
  }
}

/**
 * Thrown when attestation verification fails.
 * 
 * This covers all attestation-related security errors:
 * - Material verification failures (parsing, signatures, certificates)
 * - Policy validation failures (measurement mismatch, policy violation)
 * 
 * Examples:
 * - Data parsing failed (malformed report, invalid base64, bad structure)
 * - Sigstore signature invalid
 * - Hardware certificate chain invalid
 * - Report signature invalid
 * - Measurement mismatch (enclave code doesn't match signed release)
 * - Policy violation (debug enabled, TCB too low)
 * - Key binding mismatch (transport keys don't match attested keys)
 * 
 * Action: Stop - security issue - you should retry the entire attestation protocol.
 */
export class AttestationError extends TinfoilError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, options);
    this.name = 'AttestationError';
  }
}

/**
 * Helper to handle errors in catch blocks.
 * - If the error is already a TinfoilError, rethrow it as-is
 * - Otherwise, wrap it in the specified error class
 * 
 * @example
 * ```typescript
 * try {
 *   await someOperation();
 * } catch (e) {
 *   wrapOrThrow(e, AttestationError, 'Operation failed');
 * }
 * ```
 */
export function wrapOrThrow(
  e: unknown,
  ErrorClass: typeof AttestationError | typeof FetchError | typeof ConfigurationError,
  message: string
): never {
  if (e instanceof TinfoilError) {
    throw e;
  }
  throw new ErrorClass(message, { cause: e as Error });
}

