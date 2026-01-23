/**
 * Tinfoil Transport Singleton
 * 
 * This module provides a singleton pattern for initializing the Tinfoil SecureClient
 * and creating a transport for the Vercel AI SDK. The transport is initialized once
 * and reused across your application.
 * 
 * IMPORTANT: In browser environments, you MUST use a proxy server.
 * Set NEXT_PUBLIC_PROXY_URL to your proxy's URL.
 */

import { SecureClient } from "tinfoil";
import { DefaultChatTransport } from "ai";

// Singleton promise - initialized once, reused everywhere
let transportPromise: Promise<DefaultChatTransport> | null = null;

/**
 * Get or create the Tinfoil transport singleton.
 * 
 * This function:
 * 1. Creates a SecureClient pointing to your proxy
 * 2. Waits for attestation verification to complete
 * 3. Returns a DefaultChatTransport configured with the secure fetch
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
export function getTinfoilTransport(): Promise<DefaultChatTransport> {
  if (!transportPromise) {
    transportPromise = initializeTransport();
  }
  return transportPromise;
}

async function initializeTransport(): Promise<DefaultChatTransport> {
  // Get proxy URL from environment
  // In Next.js, use NEXT_PUBLIC_ prefix for client-side env vars
  const proxyUrl = process.env.NEXT_PUBLIC_PROXY_URL;
  
  if (!proxyUrl) {
    throw new Error(
      "NEXT_PUBLIC_PROXY_URL environment variable is required. " +
      "Set it to your proxy server URL (e.g., https://your-proxy.com)"
    );
  }

  // Create SecureClient pointing to your proxy
  // The enclaveURL is fetched automatically from the router
  const secureClient = new SecureClient({
    baseURL: proxyUrl,
  });

  // CRITICAL: Wait for attestation verification to complete
  // This verifies the enclave and exchanges encryption keys
  await secureClient.ready();

  // Create the transport with the secure fetch function
  // All request bodies will be encrypted end-to-end to the enclave
  return new DefaultChatTransport({
    api: "/v1/chat/completions",
    fetch: secureClient.fetch,
    // Optional: Add custom headers for your proxy to read
    // These are visible to your proxy but NOT to the enclave
    // headers: {
    //   "X-User-ID": getUserId(),
    // },
  });
}

/**
 * Alternative: Create transport with explicit URLs
 * 
 * Use this when you need more control over the configuration,
 * such as when using a specific enclave or custom routing.
 */
export async function createTinfoilTransport(options: {
  proxyUrl: string;
  enclaveUrl?: string;
}): Promise<DefaultChatTransport> {
  const secureClient = new SecureClient({
    baseURL: options.proxyUrl,
    enclaveURL: options.enclaveUrl,
  });

  await secureClient.ready();

  return new DefaultChatTransport({
    api: "/v1/chat/completions",
    fetch: secureClient.fetch,
  });
}
