import { isRealBrowser } from "./env.js";
import { ConfigurationError } from "./verifier.js";
import { createEncryptedBodyFetch, type SecureTransport } from "./encrypted-body-fetch.js";

/**
 * Creates a secure fetch function with either HPKE encryption or TLS pinning.
 *
 * This is the unified implementation for both browser and server environments:
 * - In browsers: Only HPKE encryption is supported (requires hpkePublicKey)
 * - In Node.js/Bun: Also supports TLS certificate pinning when configured
 *
 * All imports are dynamic to enable tree-shaking in browser bundles.
 */
export async function createSecureFetch(
  baseURL: string,
  hpkePublicKey?: string,
  tlsPublicKeyFingerprint?: string,
  enclaveURL?: string
): Promise<SecureTransport> {
  if (hpkePublicKey) {
    return createEncryptedBodyFetch(baseURL, hpkePublicKey, enclaveURL);
  }

  if (isRealBrowser()) {
    throw new ConfigurationError(
      "HPKE public key not available and TLS-only verification is not supported in browsers. " +
      "Only HPKE-enabled enclaves can be used in browser environments."
    );
  }

  if (!tlsPublicKeyFingerprint) {
    throw new ConfigurationError(
      "Neither HPKE public key nor TLS public key fingerprint available for verification"
    );
  }

  // Dynamic import to avoid including Node.js crypto module in browser bundles
  const { createPinnedTlsFetch } = await import("./pinned-tls-fetch.js");
  const pinnedFetch = await createPinnedTlsFetch(baseURL, tlsPublicKeyFingerprint);
  return {
    fetch: pinnedFetch,
    async getSessionRecoveryToken() {
      throw new Error('Session recovery tokens are only available in EHBP transport mode');
    },
  };
}