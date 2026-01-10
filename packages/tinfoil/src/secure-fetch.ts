import { createPinnedTlsFetch } from "./pinned-tls-fetch.js";
import { isRealBrowser } from "./env.js";

export async function createSecureFetch(baseURL: string, enclaveURL?: string, hpkePublicKey?: string, tlsPublicKeyFingerprint?: string): Promise<typeof fetch> {
  if (hpkePublicKey) {
    // Dynamically import encrypted-body-fetch to avoid loading ehbp/hpke modules
    // when using TLS-only mode. This prevents WebCrypto X25519 errors in runtimes
    // that don't support it (like Bun).
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

  return createPinnedTlsFetch(baseURL, tlsPublicKeyFingerprint);
}