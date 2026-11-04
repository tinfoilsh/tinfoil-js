/**
 * A provider for the Vercel AI SDK whose requests go through an attested
 * client: the discovered router by default, or one enclave when named. The
 * provider is the OpenAI-compatible one the AI SDK ships, bound to the
 * client's `fetch` and base URL, so `generateText`, `streamText` and the
 * rest send through the client's protections and stream responses as the
 * client delivers them. The attested client stays reachable from the
 * provider for its verification facts. The `tinfoil/v3/ai-sdk` entry
 * exports the factory, so the AI SDK stays out of bundles that don't use it.
 */
import { createOpenAICompatible, type OpenAICompatibleProvider } from "@ai-sdk/openai-compatible";
import { createEnclaveHTTPClient, EnclaveHTTPClient, openAIURLOf, type EnclaveClientSeams } from "../enclave-client.js";
import { ConfigurationError } from "../errors.js";
import { isServerRuntime, type RuntimeGlobals } from "./platform.js";
import type { EnclaveOptions, RouterOptions } from "../options.js";
import { createRouterHTTPClient, RouterHTTPClient, type RouterClientSeams } from "../router-client.js";

/** The enclave a provider is bound to instead of the discovered router. */
export interface TinfoilProviderEnclave {
  readonly host: string;
  /** `owner/name[@tag][@sha256:digest]`; empty accepts configs the verifier option authorizes. */
  readonly repo: string;
}

/**
 * Configures {@link createTinfoil}. Exactly one credential is given: an
 * `apiKey` on a server, or a `bearerToken` a browser page may hold. The
 * remaining options configure the attested client: the router client's when
 * `enclave` is unset, otherwise the enclave client's.
 */
export interface TinfoilProviderOptions extends Pick<RouterOptions & EnclaveOptions, "transportMode" | "baseURL" | "verifier" | "verificationCheck" | "userCacheSecret" | "signal"> {
  /** A long-lived API key, sent as the bearer credential. It belongs on a server, never in a page. */
  readonly apiKey?: string;
  /** A credential a browser page may hold, such as a short-lived token from the application's own sign-in. */
  readonly bearerToken?: string;
  /** Binds the provider to this enclave rather than the discovered router. */
  readonly enclave?: TinfoilProviderEnclave;
  /** Headers added to every request, after the credential. */
  readonly headers?: Readonly<Record<string, string>>;
}

/** The AI SDK provider, with the attested client its requests go through. */
export interface TinfoilProvider extends OpenAICompatibleProvider {
  /**
   * The client requests go through. It verifies the service again when the
   * verification expires or its key changes, and is bound to that service.
   */
  httpClient(): EnclaveHTTPClient | RouterHTTPClient;
}

/** Seams for tests: the attested clients' own, and the globals the runtime is identified by. */
export type TinfoilProviderSeams = RouterClientSeams & EnclaveClientSeams & { readonly globals?: RuntimeGlobals };

/**
 * The one credential the options carry, or a {@link ConfigurationError} when
 * there is none or more than one. A long-lived API key is refused where the
 * runtime isn't a server, as the OpenAI clients refuse it: a page or a worker
 * holds a `bearerToken` instead.
 */
function credentialOf(options: TinfoilProviderOptions, globals: RuntimeGlobals | undefined): string {
  const apiKey = options.apiKey ?? "";
  const bearerToken = options.bearerToken ?? "";
  if (apiKey !== "" && bearerToken !== "") throw new ConfigurationError("give either apiKey or bearerToken, not both");
  if (apiKey === "" && bearerToken === "") throw new ConfigurationError("a credential is required: apiKey on a server, or bearerToken in a browser");
  if (apiKey !== "" && !isServerRuntime(globals)) {
    throw new ConfigurationError("an apiKey is a long-lived credential that belongs on a server; in a browser, give a bearerToken such as a short-lived token from the application's own sign-in");
  }
  return apiKey !== "" ? apiKey : bearerToken;
}

/** The factory with its test seams; {@link createTinfoil} is this without them. */
export async function createTinfoilProvider(options: TinfoilProviderOptions, seams: TinfoilProviderSeams): Promise<TinfoilProvider> {
  // The credential is checked first, so a provider without one fails before any network I/O.
  const credential = credentialOf(options, seams.globals);
  const clientOptions = {
    transportMode: options.transportMode,
    baseURL: options.baseURL,
    verifier: options.verifier,
    verificationCheck: options.verificationCheck,
    userCacheSecret: options.userCacheSecret,
    signal: options.signal,
  };
  const client = options.enclave === undefined ? await createRouterHTTPClient(clientOptions, seams) : await createEnclaveHTTPClient(options.enclave.host, options.enclave.repo, clientOptions, seams);
  const provider = createOpenAICompatible({
    name: "tinfoil",
    baseURL: openAIURLOf(client),
    apiKey: credential,
    ...(options.headers === undefined ? {} : { headers: { ...options.headers } }),
    fetch: client.fetch as typeof globalThis.fetch,
    supportsStructuredOutputs: true,
  });
  Object.defineProperty(provider, "httpClient", { value: () => client, writable: false, configurable: false, enumerable: true });
  return provider as TinfoilProvider;
}

/**
 * A provider for the Vercel AI SDK over an attested client, verified before
 * it returns: the discovered router, or the `enclave` option. Use it with
 * `generateText`, `streamText` and the other AI SDK functions:
 *
 * ```ts
 * const tinfoil = await createTinfoil({ apiKey });
 * const { text } = await generateText({ model: tinfoil("gpt-oss-120b"), prompt: "Hello!" });
 * ```
 */
export function createTinfoil(options: TinfoilProviderOptions): Promise<TinfoilProvider> {
  return createTinfoilProvider(options, {});
}
