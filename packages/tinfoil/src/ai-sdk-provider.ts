import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { TINFOIL_CONFIG } from "./config.js";
import { SecureClient } from "./secure-client.js";

interface CreateTinfoilAIOptions {
  baseURL?: string;
  enclaveURL?: string;
  configRepo?: string;
  attestationBundleURL?: string;
}

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
