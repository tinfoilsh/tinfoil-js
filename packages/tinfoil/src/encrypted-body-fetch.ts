// Types are imported separately - type imports don't cause runtime loading
import type { Transport as EhbpTransport, Identity as EhbpIdentity } from "ehbp";
import { ConfigurationError, FetchError } from "./verifier.js";

// Lazy-loaded ehbp module - cache the promise to prevent duplicate imports on concurrent calls
let ehbpModulePromise: Promise<typeof import("ehbp")> | null = null;

function getEhbp(): Promise<typeof import("ehbp")> {
  if (!ehbpModulePromise) {
    ehbpModulePromise = import("ehbp").catch((err) => {
      ehbpModulePromise = null;
      throw err;
    });
  }
  return ehbpModulePromise;
}

/**
 * Create an Identity from a raw public key hex string.
 * This avoids fetching from the server when the key is already known.
 */
async function createIdentityFromPublicKeyHex(publicKeyHex: string): Promise<EhbpIdentity> {
  const { Identity } = await getEhbp();
  return Identity.fromPublicKeyHex(publicKeyHex);
}

/**
 * Fetch and parse server identity from the HPKE keys endpoint.
 * Returns the server Identity which can be used to create a Transport.
 */
export async function getServerIdentity(enclaveURL: string): Promise<EhbpIdentity> {
  const { Identity, PROTOCOL } = await getEhbp();
  const keysURL = new URL(PROTOCOL.KEYS_PATH, enclaveURL);

  if (keysURL.protocol !== 'https:') {
    throw new ConfigurationError(`HTTPS is required for key retrieval. Got ${keysURL.protocol}`);
  }

  const response = await fetch(keysURL.toString());

  if (!response.ok) {
    throw new FetchError(`Failed to fetch HPKE public key from enclave: HTTP ${response.status}`);
  }

  const contentType = response.headers.get('content-type');
  if (contentType !== PROTOCOL.KEYS_MEDIA_TYPE) {
    throw new FetchError(`Invalid response from HPKE key endpoint: Expected content-type "${PROTOCOL.KEYS_MEDIA_TYPE}", got "${contentType}"`);
  }

  const keysData = new Uint8Array(await response.arrayBuffer());
  return await Identity.unmarshalPublicConfig(keysData);
}

export function normalizeEncryptedBodyRequestArgs(
  input: RequestInfo | URL,
  init?: RequestInit,
): { url: string; init?: RequestInit } {
  if (typeof input === "string") {
    return { url: input, init };
  }

  if (input instanceof URL) {
    return { url: input.toString(), init };
  }

  const request = input as Request;
  const cloned = request.clone();

  const derivedInit: RequestInit = {
    method: cloned.method,
    headers: new Headers(cloned.headers),
    body: cloned.body ?? undefined,
    signal: cloned.signal,
  };

  return {
    url: cloned.url,
    init: { ...derivedInit, ...init },
  };
}

export async function encryptedBodyRequest(
  input: RequestInfo | URL,
  hpkePublicKey: string,
  init?: RequestInit,
  transportInstance?: EhbpTransport,
): Promise<Response> {
  const { url: requestUrl, init: requestInit } = normalizeEncryptedBodyRequestArgs(
    input,
    init,
  );

  let actualTransport: EhbpTransport;

  if (transportInstance) {
    actualTransport = transportInstance;
  } else {
    const u = new URL(requestUrl);
    actualTransport = await getTransportForOrigin(u.origin, hpkePublicKey);
  }

  return actualTransport.request(requestUrl, requestInit);
}

const ENCLAVE_URL_HEADER = 'X-Tinfoil-Enclave-Url';

export function createEncryptedBodyFetch(baseURL: string, hpkePublicKey: string, enclaveURL?: string): typeof fetch {
  let transportPromise: Promise<EhbpTransport> | null = null;

  const getOrCreateTransport = async (): Promise<EhbpTransport> => {
    if (!transportPromise) {
      const baseUrl = new URL(baseURL);
      transportPromise = getTransportForOrigin(baseUrl.origin, hpkePublicKey);
    }
    return transportPromise;
  };

  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const normalized = normalizeEncryptedBodyRequestArgs(input, init);
    const targetUrl = new URL(normalized.url, baseURL);

    const headers = new Headers(normalized.init?.headers);
    if (enclaveURL && new URL(enclaveURL).origin !== new URL(baseURL).origin) {
      headers.set(ENCLAVE_URL_HEADER, enclaveURL);
    }
    const initWithHeader = { ...normalized.init, headers };

    const transportInstance = await getOrCreateTransport();
    return encryptedBodyRequest(targetUrl.toString(), hpkePublicKey, initWithHeader, transportInstance);
  };
}

/**
 * WARNING: THIS FUNCTION IS INSECURE.
 *
 * Creates an encrypted body fetch that fetches the HPKE key from the server without
 * attestation verification. This is vulnerable to man-in-the-middle attacks where
 * a malicious server could provide its own key.
 *
 * This function is useful for testing the EHBP protocol against a local development
 * server that doesn't have attestation set up. For production, use createEncryptedBodyFetch
 * with a key obtained through attestation verification.
 *
 * @param baseURL - Base URL for API requests
 * @param keyOrigin - Origin URL for fetching the HPKE public key. If not provided, derived from baseURL.
 */
export function createUnverifiedEncryptedBodyFetch(baseURL: string, keyOrigin?: string): typeof fetch {
  console.warn(
    "[tinfoil] WARNING: createUnverifiedEncryptedBodyFetch is insecure. " +
    "The HPKE key is fetched from the server without attestation verification. " +
    "Only use for local development and testing of the EHBP protocol."
  );

  let transportPromise: Promise<EhbpTransport> | null = null;

  const getOrCreateTransport = async (): Promise<EhbpTransport> => {
    if (!transportPromise) {
      const baseUrl = new URL(baseURL);
      const resolvedKeyOrigin = keyOrigin ? new URL(keyOrigin).origin : baseUrl.origin;
      transportPromise = getUnverifiedTransportForOrigin(baseUrl.origin, resolvedKeyOrigin);
    }
    return transportPromise;
  };

  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const normalized = normalizeEncryptedBodyRequestArgs(input, init);
    const targetUrl = new URL(normalized.url, baseURL);

    const headers = new Headers(normalized.init?.headers);
    if (keyOrigin && new URL(keyOrigin).origin !== new URL(baseURL).origin) {
      headers.set(ENCLAVE_URL_HEADER, keyOrigin);
    }
    const initWithEnclaveHeader = { ...normalized.init, headers };

    const transportInstance = await getOrCreateTransport();
    return transportInstance.request(targetUrl.toString(), initWithEnclaveHeader);
  };
}

async function getUnverifiedTransportForOrigin(origin: string, keyOrigin: string): Promise<EhbpTransport> {
  if (typeof globalThis !== 'undefined') {
    const isSecure = (globalThis as any).isSecureContext !== false;
    const hasSubtle = !!(globalThis.crypto && (globalThis.crypto as Crypto).subtle);
    if (!isSecure || !hasSubtle) {
      const reason = !isSecure ? 'Use HTTPS or localhost' : 'WebCrypto SubtleCrypto API is not available';
      throw new ConfigurationError(`EHBP encryption requires a secure browser context: ${reason}`);
    }
  }

  const { Transport } = await getEhbp();
  const serverIdentity = await getServerIdentity(keyOrigin);
  const requestHost = new URL(origin).host;
  return new Transport(serverIdentity, requestHost);
}

export async function getTransportForOrigin(origin: string, hpkePublicKeyHex: string): Promise<EhbpTransport> {
  if (typeof globalThis !== 'undefined') {
    const isSecure = (globalThis as any).isSecureContext !== false;
    const hasSubtle = !!(globalThis.crypto && (globalThis.crypto as Crypto).subtle);
    if (!isSecure || !hasSubtle) {
      const reason = !isSecure ? 'Use HTTPS or localhost' : 'WebCrypto SubtleCrypto API is not available';
      throw new ConfigurationError(`EHBP encryption requires a secure browser context: ${reason}`);
    }
  }

  const { Transport } = await getEhbp();
  const serverIdentity = await createIdentityFromPublicKeyHex(hpkePublicKeyHex);
  const requestHost = new URL(origin).host;
  return new Transport(serverIdentity, requestHost);
}
