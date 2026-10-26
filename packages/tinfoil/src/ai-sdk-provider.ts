import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { Client, type ClientOptions } from "./client.js";
import { Gateway, type GatewayOptions } from "./gateway.js";
import { isRealBrowser } from "./env.js";
import { ConfigurationError } from "./errors.js";
export interface CreateTinfoilAIOptions extends ClientOptions {
  gateway?: GatewayOptions & { url: string };
}
/** OpenAI-compatible AI SDK provider with native structured-output serialization. */
export async function createTinfoilAI(apiKey?: string, options: CreateTinfoilAIOptions = {}) {
  const resolved = apiKey || (!isRealBrowser() && typeof process !== "undefined" ? process.env.TINFOIL_API_KEY : undefined);
  if (!resolved) throw new ConfigurationError("API key is required");
  if (options.gateway && [options.enclaveURL, options.configRepo, options.baseURL, options.transport].some(value => value !== undefined)) throw new ConfigurationError("Gateway configuration owns endpoints, repositories and EHBP transport");
  const secure = options.gateway
    ? new Gateway(options.gateway.url, { verification: options.verification, acquisition: options.acquisition, userCacheSecret: options.userCacheSecret, ...options.gateway })
    : new Client(options);
  if (!options.gateway) await secure.ready();
  return createOpenAICompatible({ name: "tinfoil", baseURL: secure.getBaseURL(), apiKey: resolved, fetch: secure.fetch, supportsStructuredOutputs: true });
}
