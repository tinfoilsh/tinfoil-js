import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { TINFOIL_CONFIG } from "./config.js";
import { SecureClient } from "./secure-client.js";

/**
 * Options for creating a Tinfoil AI SDK provider.
 */
export interface CreateTinfoilAIOptions {
  /** 
   * Override the base URL for API requests. 
   * Useful for proxying requests through your own backend.
   */
  baseURL?: string;
  
  /** 
   * Override the enclave URL for verification and key fetching.
   */
  enclaveURL?: string;
  
  /** GitHub repo for release verification. */
  configRepo?: string;
  /**
   * Optional URL to fetch a precomputed attestation bundle from.
   *
   * This is primarily useful when you want verification to use an externally
   * produced bundle (e.g., fetched via your own routing layer) instead of
   * letting the client fetch it from the default router flow.
   */
  attestationBundleURL?: string;
}

/**
 * Create a Tinfoil provider for the Vercel AI SDK.
 * 
 * This performs enclave verification and returns an OpenAI-compatible provider
 * that can be used with Vercel AI SDK functions like `generateText` and `streamText`.
 * 
 * @param apiKey - Your Tinfoil API key
 * @param options - Optional configuration
 * @returns An AI SDK provider for Tinfoil
 * 
 * @example
 * ```typescript
 * import { createTinfoilAI } from "tinfoil";
 * import { generateText } from "ai";
 * 
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
export async function createTinfoilAI(apiKey: string, options: CreateTinfoilAIOptions = {}) {
  const baseURL = options.baseURL;
  const enclaveURL = options.enclaveURL;
  const configRepo = options.configRepo || TINFOIL_CONFIG.DEFAULT_ROUTER_REPO;

  const secureClient = new SecureClient({
    baseURL,
    enclaveURL,
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
    apiKey: apiKey,
    fetch: secureClient.fetch,
  });
}
