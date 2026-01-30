import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { TINFOIL_CONFIG } from "./config.js";
import { SecureClient } from "./secure-client.js";
import { isRealBrowser } from "./env.js";

/**
 * Options for creating a Tinfoil AI SDK provider.
 */
export interface CreateTinfoilAIOptions {
  /**
   * Override the base URL for API requests.
   * Useful for proxying requests through your own backend.
   */
  baseURL?: string;

  /** GitHub repo for code verification. */
  configRepo?: string;

  /** URL to fetch the attestation bundle from. */
  attestationBundleURL?: string;
}

/**
 * Create a Tinfoil provider for the Vercel AI SDK.
 * 
 * This performs enclave verification and returns an OpenAI-compatible provider
 * that can be used with Vercel AI SDK functions like `generateText` and `streamText`.
 * 
 * @param apiKey - Your Tinfoil API key. Falls back to TINFOIL_API_KEY env var if not provided.
 * @param options - Optional configuration
 * @returns An AI SDK provider for Tinfoil
 *
 * @example
 * ```typescript
 * import { createTinfoilAI } from "tinfoil";
 * import { generateText } from "ai";
 *
 * // Uses TINFOIL_API_KEY env var
 * const tinfoil = await createTinfoilAI();
 *
 * // Or pass API key explicitly
 * const tinfoil = await createTinfoilAI("your-api-key");
 *
 * const { text } = await generateText({
 *   model: tinfoil("llama3-3-70b"),
 *   prompt: "Hello!",
 * });
 * ```
 *
 * @see https://docs.tinfoil.sh/sdk/javascript-sdk
 * @see https://sdk.vercel.ai/ - Vercel AI SDK documentation
 */
export async function createTinfoilAI(apiKey?: string, options: CreateTinfoilAIOptions = {}) {
  // Resolve API key: use provided value, or fall back to env var (non-browser only)
  let resolvedApiKey = apiKey;
  if (!resolvedApiKey && !isRealBrowser() && typeof process !== 'undefined' && process.env.TINFOIL_API_KEY) {
    resolvedApiKey = process.env.TINFOIL_API_KEY;
  }
  if (!resolvedApiKey) {
    throw new Error("API key is required. Provide apiKey parameter or set TINFOIL_API_KEY environment variable.");
  }

  const baseURL = options.baseURL;
  const configRepo = options.configRepo || TINFOIL_CONFIG.DEFAULT_ROUTER_REPO;

  const secureClient = new SecureClient({
    baseURL,
    configRepo,
    attestationBundleURL: options.attestationBundleURL,
  });

  await secureClient.ready();

  // Get the baseURL from SecureClient after initialization
  const finalBaseURL = baseURL || secureClient.getBaseURL();
  if (!finalBaseURL) {
    throw new Error("Unable to determine baseURL for AI SDK provider");
  }

  return createOpenAICompatible({
    name: "tinfoil",
    baseURL: finalBaseURL,
    apiKey: resolvedApiKey,
    fetch: secureClient.fetch,
  });
}
