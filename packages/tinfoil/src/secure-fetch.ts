import { isRealBrowser } from "./env.js";
import { ProtocolError } from "ehbp";
import { ConfigurationError, AttestationError } from "./errors.js";
import { createEncryptedBodyFetch, type SecureTransport } from "./encrypted-body-fetch.js";
import { withUserCacheSecret } from "./user-cache-secret.js";

/**
 * Creates a secure fetch function with either HPKE encryption or TLS pinning.
 *
 * This is the unified implementation for both browser and server environments:
 * - In browsers: Only HPKE encryption is supported (requires hpkePublicKey)
 * - In Node.js/Bun: Also supports TLS certificate pinning when configured
 *
 * A non-empty userCacheSecret is injected into eligible request bodies inside
 * the sealing boundary (EHBP body encryption or the pinned TLS connection),
 * so the secret never travels outside the protected channel.
 *
 * The pinned-tls-fetch import is dynamic to keep Node.js-only code out of browser bundles.
 */
export async function createSecureFetch(
  baseURL: string,
  hpkePublicKey?: string,
  tlsPublicKeyFingerprint?: string,
  enclaveURL?: string,
  userCacheSecret: string = ""
): Promise<SecureTransport> {
  if (hpkePublicKey) {
    const transport = createEncryptedBodyFetch(baseURL, hpkePublicKey, enclaveURL, userCacheSecret);
    try { await transport.initialize!(); } catch (cause) {
      if (cause instanceof ProtocolError) throw new AttestationError("Attested HPKE key could not initialize a secure channel", { cause });
      throw cause;
    }
    return transport;
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
    // The cache-secret layer wraps the pinned fetch, so the field it injects
    // only ever travels over the connection pinned to the attested key.
    fetch: withUserCacheSecret(pinnedFetch, baseURL, userCacheSecret),
    async getSessionRecoveryToken() {
      throw new Error('Session recovery tokens are only available in EHBP transport mode');
    },
  };
}