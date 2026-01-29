// Types are imported separately - type imports don't cause runtime loading
import type { Transport as EhbpTransport, Identity as EhbpIdentity } from "ehbp";

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
    throw new Error(`HTTPS is required for remote key retrieval. Invalid protocol: ${keysURL.protocol}`);
  }

  const response = await fetch(keysURL.toString());

  if (!response.ok) {
    throw new Error(`Failed to get server public key: ${response.status}`);
  }

  const contentType = response.headers.get('content-type');
  if (contentType !== PROTOCOL.KEYS_MEDIA_TYPE) {
    throw new Error(`Invalid content type: ${contentType}`);
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

// Extended fetch type that includes Response property for OpenAI SDK compatibility
type FetchWithResponse = typeof fetch & { Response: typeof Response };

const ENCLAVE_URL_HEADER = 'X-Tinfoil-Enclave-Url';

export function createEncryptedBodyFetch(baseURL: string, hpkePublicKey?: string, enclaveURL?: string): FetchWithResponse {
  // Create a dedicated transport instance for this fetch function
  let transportPromise: Promise<EhbpTransport> | null = null;

  const getOrCreateTransport = async (): Promise<EhbpTransport> => {
    if (!transportPromise) {
      if (!hpkePublicKey) {
        throw new Error("HPKE public key is required for verified encrypted body fetch");
      }
      const baseUrl = new URL(baseURL);
      transportPromise = getTransportForOrigin(baseUrl.origin, hpkePublicKey);
    }
    return transportPromise;
  };

  const secureFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const normalized = normalizeEncryptedBodyRequestArgs(input, init);
    const targetUrl = new URL(normalized.url, baseURL);

    // Add the enclave URL header so proxies know where to forward requests
    // Only set if enclaveURL differs from baseURL (avoids CORS issues when hitting enclave directly)
    const headers = new Headers(normalized.init?.headers);
    if (enclaveURL && new URL(enclaveURL).origin !== new URL(baseURL).origin) {
      headers.set(ENCLAVE_URL_HEADER, enclaveURL);
    }
    const initWithEnclaveHeader = { ...normalized.init, headers };

    // Get the dedicated transport instance for this fetch function
    const transportInstance = await getOrCreateTransport();

    return encryptedBodyRequest(targetUrl.toString(), hpkePublicKey!, initWithEnclaveHeader, transportInstance);
  }) as FetchWithResponse;

  // Expose Response constructor for OpenAI SDK's FormData support detection
  // This prevents the SDK from making a test request to 'data:,' which would fail through EHBP
  secureFetch.Response = Response;

  return secureFetch;
}

/**
 * Creates an encrypted body fetch that fetches the HPKE key from the server.
 * Only use for development/testing - production should use createEncryptedBodyFetch with a verified key.
 */
export function createUnverifiedEncryptedBodyFetch(baseURL: string, enclaveURL?: string): FetchWithResponse {
  let transportPromise: Promise<EhbpTransport> | null = null;

  const getOrCreateTransport = async (): Promise<EhbpTransport> => {
    if (!transportPromise) {
      const baseUrl = new URL(baseURL);
      const keyOrigin = enclaveURL ? new URL(enclaveURL).origin : baseUrl.origin;
      transportPromise = getUnverifiedTransportForOrigin(baseUrl.origin, keyOrigin);
    }
    return transportPromise;
  };

  const secureFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const normalized = normalizeEncryptedBodyRequestArgs(input, init);
    const targetUrl = new URL(normalized.url, baseURL);

    const headers = new Headers(normalized.init?.headers);
    if (enclaveURL && new URL(enclaveURL).origin !== new URL(baseURL).origin) {
      headers.set(ENCLAVE_URL_HEADER, enclaveURL);
    }
    const initWithEnclaveHeader = { ...normalized.init, headers };

    const transportInstance = await getOrCreateTransport();
    return transportInstance.request(targetUrl.toString(), initWithEnclaveHeader);
  }) as FetchWithResponse;

  secureFetch.Response = Response;
  return secureFetch;
}

async function getUnverifiedTransportForOrigin(origin: string, keyOrigin: string): Promise<EhbpTransport> {
  if (typeof globalThis !== 'undefined') {
    const isSecure = (globalThis as any).isSecureContext !== false;
    const hasSubtle = !!(globalThis.crypto && (globalThis.crypto as Crypto).subtle);
    if (!isSecure || !hasSubtle) {
      const reason = !isSecure ? 'insecure context (use HTTPS or localhost)' : 'missing WebCrypto SubtleCrypto';
      throw new Error(`EHBP requires a secure browser context: ${reason}`);
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
      const reason = !isSecure ? 'insecure context (use HTTPS or localhost)' : 'missing WebCrypto SubtleCrypto';
      throw new Error(`EHBP requires a secure browser context: ${reason}`);
    }
  }

  const { Transport } = await getEhbp();
  const serverIdentity = await createIdentityFromPublicKeyHex(hpkePublicKeyHex);
  const requestHost = new URL(origin).host;
  return new Transport(serverIdentity, requestHost);
}
