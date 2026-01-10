export async function createSecureFetch(baseURL: string, enclaveURL?: string, hpkePublicKey?: string, tlsPublicKeyFingerprint?: string): Promise<typeof fetch> {
    if (hpkePublicKey) {
        // Dynamic import to avoid loading ehbp/hpke at module load time
        const { createEncryptedBodyFetch } = await import("./encrypted-body-fetch.js");
        return createEncryptedBodyFetch(baseURL, hpkePublicKey, enclaveURL);
    } else {
        throw new Error(
            "HPKE public key not available and TLS-only verification is not supported in browsers. " +
            "Only HPKE-enabled enclaves can be used in browser environments."
        );
    }
}
