/**
 * Tinfoil Transport Singleton
 *
 * This module provides a singleton pattern for creating the attested Tinfoil
 * HTTP client and a transport for the Vercel AI SDK. The transport is
 * initialized once and reused across your application.
 */

import { EnclaveHTTPClient, RouterHTTPClient } from "tinfoil";
import { DefaultChatTransport, UIMessage } from "ai";

// Singleton promise - initialized once, reused everywhere
let transportPromise: Promise<DefaultChatTransport<UIMessage>> | null = null;

/**
 * Get or create the Tinfoil transport singleton.
 *
 * This function:
 * 1. Creates a RouterHTTPClient routed through your proxy, which verifies
 *    the enclave's attestation before the client is returned
 * 2. Returns a DefaultChatTransport configured with the client's fetch
 *
 * The transport is cached and reused on subsequent calls.
 *
 * @example
 * ```tsx
 * // In a React component
 * const [transport, setTransport] = useState<DefaultChatTransport | null>(null);
 *
 * useEffect(() => {
 *   getTinfoilTransport().then(setTransport);
 * }, []);
 * ```
 */
export function getTinfoilTransport(): Promise<DefaultChatTransport<UIMessage>> {
  if (!transportPromise) {
    transportPromise = initializeTransport();
  }
  return transportPromise;
}

async function initializeTransport(): Promise<DefaultChatTransport<UIMessage>> {
  // Get proxy URL from environment
  // In Next.js, use NEXT_PUBLIC_ prefix for client-side env vars
  const proxyUrl = process.env.NEXT_PUBLIC_PROXY_URL;

  if (!proxyUrl) {
    throw new Error(
      "NEXT_PUBLIC_PROXY_URL environment variable is required. " +
      "Set it to your proxy server URL (e.g., https://your-proxy.com)"
    );
  }

  // Create the client, routing requests through your proxy. The factory
  // verifies the enclave and returns only once verification succeeds; in a
  // browser, request bodies are encrypted end-to-end to the enclave, and the
  // proxy forwards them to the host named by the X-Tinfoil-Enclave-Url header.
  const client = await RouterHTTPClient.create({
    baseURL: proxyUrl,
  });

  // Create the transport with the client's fetch. Request URLs are absolute,
  // so the API path is resolved against where the client's requests go,
  // which ends with "/" and keeps any path the proxy base URL carries.
  return new DefaultChatTransport({
    api: new URL("v1/chat/completions", client.baseURL).href,
    fetch: client.fetch,
    // Optional: If using a proxy, add custom headers for it to read.
    // These headers are visible to your proxy but the body remains encrypted.
    // headers: {
    //   "X-User-ID": getUserId(),
    // },
  });
}

/**
 * Alternative: Create transport for one named enclave
 *
 * Use this when you need more control over the configuration,
 * such as when using a specific enclave rather than the discovered router.
 */
export async function createTinfoilTransport(options: {
  proxyUrl: string;
  enclaveHost: string;
  repo: string;
}): Promise<DefaultChatTransport<UIMessage>> {
  const client = await EnclaveHTTPClient.create(options.enclaveHost, options.repo, {
    baseURL: options.proxyUrl,
  });

  return new DefaultChatTransport({
    api: new URL("v1/chat/completions", client.baseURL).href,
    fetch: client.fetch,
  });
}
