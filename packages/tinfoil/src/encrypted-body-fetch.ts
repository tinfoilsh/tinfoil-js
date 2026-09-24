import { Identity, Transport, PROTOCOL, type SessionRecoveryToken } from "ehbp";
import { AttestationError, ConfigurationError, FetchError } from "./verifier.js";
import { injectUserCacheSecretIntoRequestInit, withRoutingHeaders } from "./user-cache-secret.js";

export type { SessionRecoveryToken } from "ehbp";
export { decryptResponseWithToken } from "ehbp";

export interface SecureTransport {
  fetch: typeof fetch;
  getSessionRecoveryToken(): Promise<SessionRecoveryToken>;
}

/**
 * Create an Identity from a raw public key hex string.
 * This avoids fetching from the server when the key is already known.
 */
async function createIdentityFromPublicKeyHex(publicKeyHex: string): Promise<Identity> {
  return Identity.fromPublicKeyHex(publicKeyHex);
}

/**
 * Fetch and parse server identity from the HPKE keys endpoint.
 * Returns the server Identity which can be used to create a Transport.
 */
export async function getServerIdentity(enclaveURL: string): Promise<Identity> {
  const keysURL = new URL(PROTOCOL.KEYS_PATH, enclaveURL);

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

  const request = new Request(input as Request, init);

  return {
    url: request.url,
    init: requestInitFromRequest(request),
  };
}

function requestInitFromRequest(
  request: Request,
  body: BodyInit | null = request.body,
): RequestInit {
  const requestWithExtensions = request as Request & {
    duplex?: "half";
    priority?: RequestPriority;
  };
  const derivedInit: RequestInit & {
    duplex?: "half";
    priority?: RequestPriority;
  } = {
    method: request.method,
    headers: new Headers(request.headers),
    body: body ?? undefined,
    cache: request.cache,
    credentials: request.credentials,
    integrity: request.integrity,
    keepalive: request.keepalive,
    mode: request.mode,
    redirect: request.redirect,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
    signal: request.signal,
  };
  if (requestWithExtensions.duplex !== undefined) {
    derivedInit.duplex = requestWithExtensions.duplex;
  }
  if (requestWithExtensions.priority !== undefined) {
    derivedInit.priority = requestWithExtensions.priority;
  }
  return derivedInit;
}

export async function encryptedBodyRequest(
  input: RequestInfo | URL,
  hpkePublicKey: string,
  init?: RequestInit,
  transportInstance?: Transport,
): Promise<Response> {
  const { url: requestUrl, init: requestInit } = normalizeEncryptedBodyRequestArgs(
    input,
    init,
  );

  let actualTransport: Transport;

  if (transportInstance) {
    actualTransport = transportInstance;
  } else {
    const u = new URL(requestUrl);
    actualTransport = await getTransportForOrigin(u.origin, hpkePublicKey);
  }

  return actualTransport.request(requestUrl, requestInit);
}

const ENCLAVE_URL_HEADER = 'X-Tinfoil-Enclave-Url';
const SEAL_HEADER = 'X-Tinfoil-Seal';
// Not 422: ehbp claims that status for its own key-config mismatch problem.
const RESEAL_STATUS = 421;
const MAX_SEAL_REDIRECTS = 3;

export type ResealFn = (enclaveURL: string) => Promise<string>;

export function createEncryptedBodyFetch(baseURL: string, hpkePublicKey: string, enclaveURL?: string, userCacheSecret: string = "", reseal?: ResealFn): SecureTransport {
  const base = new URL(baseURL);
  const baseOrigin = base.origin;
  const needsEnclaveHeader = !!enclaveURL && new URL(enclaveURL).origin !== baseOrigin;

  // Bind requests to the verified enclave and the configured proxy. EHBP only
  // seals the body, so request headers (which may carry the API key) travel in
  // plaintext; sending them to any other origin would leak them.
  const allowedOrigins = new Set<string>([baseOrigin]);
  if (enclaveURL) {
    allowedOrigins.add(new URL(enclaveURL).origin);
  }

  const initialSeal = enclaveURL ? new URL(enclaveURL).host : "";
  let activeSeal = initialSeal;
  const transports = new Map<string, Promise<Transport>>();

  const enclaveURLForSeal = (seal: string): string =>
    seal === initialSeal ? enclaveURL! : `https://${seal}`;

  const transportFor = (seal: string): Promise<Transport> => {
    let pending = transports.get(seal);
    if (!pending) {
      pending = (seal === initialSeal
        ? Promise.resolve(hpkePublicKey)
        : reseal!(`https://${seal}`)
      ).then((key) => getTransportForOrigin(baseOrigin, key));
      pending.catch(() => transports.delete(seal));
      transports.set(seal, pending);
    }
    return pending;
  };

  const follow = async (seal: string): Promise<void> => {
    try {
      await transportFor(seal);
    } catch (cause) {
      throw new AttestationError(
        `gateway routed to enclave ${seal}, which failed verification`,
        { cause: cause as Error },
      );
    }
    activeSeal = seal;
  };

  return {
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const normalized = normalizeEncryptedBodyRequestArgs(input, init);
      const targetUrl = new URL(normalized.url, baseURL);
      if (!allowedOrigins.has(targetUrl.origin)) {
        throw new ConfigurationError(
          `refusing to send request to ${targetUrl.origin}: this client is bound to the verified enclave/proxy`
        );
      }

      // Injected inside the origin guard, so the secret is sealed with the body.
      const injected = await injectUserCacheSecretIntoRequestInit(
        { ...normalized.init },
        targetUrl.pathname,
        userCacheSecret,
      );
      // The gateway routes on plaintext headers because it cannot open the body.
      const routedInit = (await withRoutingHeaders(
        injected,
        targetUrl.pathname,
        userCacheSecret,
      ))!;

      const pinnedSeal = new Headers(routedInit.headers).get(SEAL_HEADER);
      const honorPin =
        pinnedSeal !== null && (reseal !== undefined || pinnedSeal === initialSeal);

      for (let attempt = 0; ; attempt++) {
        const seal = attempt === 0 && honorPin ? pinnedSeal! : activeSeal;
        const headers = new Headers(routedInit.headers);
        if (needsEnclaveHeader) {
          headers.set(ENCLAVE_URL_HEADER, enclaveURLForSeal(seal));
        }
        if (seal) {
          headers.set(SEAL_HEADER, seal);
        }

        const transport = await transportFor(seal);
        const response = await transport.request(targetUrl.toString(), {
          ...routedInit,
          headers,
        });

        const routedTo = response.headers.get(SEAL_HEADER);
        if (
          !reseal ||
          response.status !== RESEAL_STATUS ||
          !routedTo ||
          routedTo === seal
        ) {
          return response;
        }
        await response.body?.cancel();

        if (attempt === MAX_SEAL_REDIRECTS) {
          throw new FetchError(
            `gateway kept routing away from the enclave the request was sealed to (last: ${routedTo})`
          );
        }
        await follow(routedTo);
      }
    },

    async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
      const pending = transports.get(activeSeal);
      if (!pending) {
        throw new Error('No session recovery token available — no request has been made yet');
      }
      return (await pending).getSessionRecoveryToken();
    },
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
export function createUnverifiedEncryptedBodyFetch(baseURL: string, keyOrigin?: string): SecureTransport {
  console.warn(
    "[tinfoil] WARNING: createUnverifiedEncryptedBodyFetch is insecure. " +
    "The HPKE key is fetched from the server without attestation verification. " +
    "Only use for local development and testing of the EHBP protocol."
  );

  const baseOrigin = new URL(baseURL).origin;
  const resolvedKeyOrigin = keyOrigin ? new URL(keyOrigin).origin : baseOrigin;
  const needsEnclaveHeader = !!keyOrigin && resolvedKeyOrigin !== baseOrigin;

  let transportPromise: Promise<Transport> | null = null;

  const getOrCreateTransport = async (): Promise<Transport> => {
    if (!transportPromise) {
      transportPromise = getUnverifiedTransportForOrigin(baseOrigin, resolvedKeyOrigin);
    }
    return transportPromise;
  };

  return {
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const normalized = normalizeEncryptedBodyRequestArgs(input, init);
      const targetUrl = new URL(normalized.url, baseURL);

      const headers = new Headers(normalized.init?.headers);
      if (needsEnclaveHeader) {
        headers.set(ENCLAVE_URL_HEADER, keyOrigin!);
      }
      const initWithEnclaveHeader = { ...normalized.init, headers };

      const transportInstance = await getOrCreateTransport();
      return transportInstance.request(targetUrl.toString(), initWithEnclaveHeader);
    },

    async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
      if (!transportPromise) {
        throw new Error('No session recovery token available — no request has been made yet');
      }
      const transport = await transportPromise;
      return transport.getSessionRecoveryToken();
    },
  };
}

async function getUnverifiedTransportForOrigin(origin: string, keyOrigin: string): Promise<Transport> {
  const serverIdentity = await getServerIdentity(keyOrigin);
  const requestHost = new URL(origin).host;
  return new Transport(serverIdentity, requestHost);
}

async function getTransportForOrigin(origin: string, hpkePublicKeyHex: string): Promise<Transport> {
  const serverIdentity = await createIdentityFromPublicKeyHex(hpkePublicKeyHex);
  const requestHost = new URL(origin).host;
  return new Transport(serverIdentity, requestHost);
}
