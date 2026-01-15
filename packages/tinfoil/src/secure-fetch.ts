import { isRealBrowser } from "./env.js";

/**
 * Creates a secure fetch function with either HPKE encryption or TLS pinning.
 * 
 * This is the unified implementation for both browser and server environments:
 * - In browsers: Only HPKE encryption is supported (requires hpkePublicKey)
 * - In Node.js/Bun: Falls back to TLS certificate pinning if HPKE unavailable
 * 
 * All imports are dynamic to enable tree-shaking in browser bundles.
 */
export async function createSecureFetch(
  baseURL: string,
  enclaveURL?: string,
  hpkePublicKey?: string,
  tlsPublicKeyFingerprint?: string
): Promise<typeof fetch> {
  if (hpkePublicKey) {
    // Dynamic import to avoid loading ehbp/hpke modules when using TLS-only mode.
    // This prevents WebCrypto X25519 errors in runtimes that don't support it (like Bun).
    const { createEncryptedBodyFetch } = await import("./encrypted-body-fetch.js");
    return createEncryptedBodyFetch(baseURL, hpkePublicKey, enclaveURL);
  }

  if (isRealBrowser()) {
    throw new Error(
      "HPKE public key not available and TLS-only verification is not supported in browsers. " +
      "Only HPKE-enabled enclaves can be used in browser environments."
    );
  }

  if (!tlsPublicKeyFingerprint) {
    throw new Error(
      "Neither HPKE public key nor TLS public key fingerprint available for verification"
    );
  }

  // Dynamic import to avoid including Node.js crypto module in browser bundles
  const { createPinnedTlsFetch } = await import("./pinned-tls-fetch.js");
  return createPinnedTlsFetch(baseURL, tlsPublicKeyFingerprint);
}