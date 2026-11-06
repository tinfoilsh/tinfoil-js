/**
 * Tinfoil Transport for `useChat`
 *
 * `useChat` speaks the AI SDK's own protocol to its transport: it hands the
 * transport UI messages and reads back a stream of UI message chunks. The
 * enclave speaks the OpenAI chat completions API, so a transport that posted
 * the hook's requests to `/v1/chat/completions` would fail on both sides.
 * The transport here translates: it converts the UI messages to model
 * messages, runs `streamText` over an OpenAI-compatible provider whose fetch
 * is the attested client's, and returns the result as the UI message stream
 * the hook expects. Every request goes through the client's protections,
 * with its body encrypted end-to-end to the enclave.
 *
 * The provider carries no credential: the proxy adds your API key, so the
 * browser never holds it. The transport is created once and reused across
 * your application.
 */

import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { convertToModelMessages, streamText, type ChatTransport, type UIMessage, type UIMessageChunk } from "ai";
import { EnclaveHTTPClient, RouterHTTPClient } from "tinfoil";

// Model to use - must match your Tinfoil model catalog
// See: https://docs.tinfoil.sh/models/catalog
const MODEL = "gpt-oss-120b";

type SendOptions = Parameters<ChatTransport<UIMessage>["sendMessages"]>[0];

/** A `useChat` transport whose requests go through an attested Tinfoil client. */
export class TinfoilChatTransport implements ChatTransport<UIMessage> {
  private readonly provider: ReturnType<typeof createOpenAICompatible>;
  private readonly model: string;

  constructor(client: EnclaveHTTPClient | RouterHTTPClient, model: string = MODEL) {
    this.provider = createOpenAICompatible({
      name: "tinfoil",
      // The client's base URL ends with "/" and keeps any path the proxy URL
      // carries, so the API path resolves against where its requests go.
      baseURL: new URL("v1", client.baseURL).href,
      fetch: client.fetch,
      // Optional: If using a proxy, add custom headers for it to read.
      // These headers are visible to your proxy but the body remains encrypted.
      // headers: {
      //   "X-User-ID": getUserId(),
      // },
    });
    this.model = model;
  }

  async sendMessages({ messages, abortSignal }: SendOptions): Promise<ReadableStream<UIMessageChunk>> {
    const result = streamText({
      model: this.provider(this.model),
      messages: await convertToModelMessages(messages),
      abortSignal,
    });
    return result.toUIMessageStream();
  }

  async reconnectToStream(): Promise<ReadableStream<UIMessageChunk> | null> {
    // The reply streams straight from the enclave; there is no server-side
    // stream to pick up again after a reload.
    return null;
  }
}

// Singleton promise - initialized once, reused everywhere
let transportPromise: Promise<TinfoilChatTransport> | null = null;

/**
 * Get or create the Tinfoil transport singleton.
 *
 * This function:
 * 1. Creates a RouterHTTPClient routed through your proxy, which verifies
 *    the enclave's attestation before the client is returned
 * 2. Returns a TinfoilChatTransport over the client
 *
 * The transport is cached and reused on subsequent calls.
 *
 * @example
 * ```tsx
 * // In a React component
 * const [transport, setTransport] = useState<TinfoilChatTransport | null>(null);
 *
 * useEffect(() => {
 *   getTinfoilTransport().then(setTransport);
 * }, []);
 * ```
 */
export function getTinfoilTransport(): Promise<TinfoilChatTransport> {
  if (!transportPromise) {
    transportPromise = initializeTransport();
  }
  return transportPromise;
}

async function initializeTransport(): Promise<TinfoilChatTransport> {
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

  return new TinfoilChatTransport(client);
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
  model?: string;
}): Promise<TinfoilChatTransport> {
  const client = await EnclaveHTTPClient.create(options.enclaveHost, options.repo, {
    baseURL: options.proxyUrl,
  });

  return new TinfoilChatTransport(client, options.model);
}
