/**
 * Browser stub for pinned-tls-fetch.
 * TLS certificate pinning is not supported in browsers as they don't expose low-level TLS APIs.
 * This module should never be called in browser environments - the runtime check in
 * secure-fetch.ts throws before reaching this code. This stub exists to satisfy bundlers.
 */
import { ConfigurationError } from "./verifier.js";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function createPinnedTlsFetch(baseURL: string, expectedFingerprintHex: string): Promise<typeof fetch> {
  throw new ConfigurationError(
    "TLS certificate pinning is not supported in browser environments. " +
    "This should not have been called - please report this as a bug."
  );
}
