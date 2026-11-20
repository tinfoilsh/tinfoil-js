/**
 * A provider for the Vercel AI SDK whose requests go through an attested
 * client: the discovered router by default, or one enclave when named. The
 * provider is the OpenAI-compatible one the AI SDK ships, bound to the
 * client's `fetch` and base URL, so `generateText`, `streamText` and the
 * rest send through the client's protections and stream responses as the
 * client delivers them. The attested client stays reachable from the
 * provider for its verification facts. The `tinfoil/ai-sdk` entry
 * exports the factory, so the AI SDK stays out of bundles that don't use it.
 */
import { createOpenAICompatible, type OpenAICompatibleProvider } from "@ai-sdk/openai-compatible";
import { createEnclaveHTTPClient, EnclaveHTTPClient, type EnclaveClientSeams } from "../enclave-client.js";
import { apiBaseURL, validateAPIPath } from "./api-path.js";
import { ConfigurationError } from "../errors.js";
import { checkAPIKeyRuntime } from "./credential.js";
import type { RuntimeGlobals } from "./platform.js";
import type { EnclaveOptions, RouterListFetcher, RouterOptions } from "../options.js";
import { createRouterHTTPClient, RouterHTTPClient, type RouterClientSeams } from "../router-client.js";
import type { Trust } from "../trust.js";

/** The enclave a provider is bound to instead of the discovered router. */
export interface TinfoilProviderEnclave {
  readonly host: string;
  /** Who vouches for the enclave's config, as for {@link EnclaveHTTPClient.create}. */
  readonly trust: Trust;
}

/** The options of {@link createTinfoil} that both routes take. */
export interface TinfoilProviderBaseOptions extends Pick<RouterOptions & EnclaveOptions, "transport" | "policy" | "verificationCheck" | "fetchAttestation" | "signal"> {
  /** A long-lived API key, sent as the bearer credential. It belongs on a server, never in a page. */
  readonly apiKey?: string;
  /** A credential a browser page may hold, such as a short-lived token from the application's own sign-in. */
  readonly bearerToken?: string;
  /**
   * The path of the API on the enclave or router, joined under the EHBP
   * proxy when one is set and under the enclave's origin otherwise; undefined
   * selects `/v1/`. As for the OpenAI client's `apiPath`.
   */
  readonly apiPath?: string;
  /** Headers added to every request, after the credential. */
  readonly headers?: Readonly<Record<string, string>>;
}

/**
 * Configures {@link createTinfoil}. Exactly one credential is given: an
 * `apiKey` on a server, or a `bearerToken` a browser page may hold. The
 * remaining options configure the attested client: the router client's when
 * `enclave` is unset, otherwise the enclave client's. `userCacheSecret` is
 * the router client's option: an enclave client never adds a
 * `user_cache_secret`, so the two can't be given together.
 */
export type TinfoilProviderOptions = TinfoilProviderBaseOptions &
  (
    | {
        readonly enclave?: undefined;
        /** As for the router client's `userCacheSecret`. */
        readonly userCacheSecret?: string;
        /** As for the router client's `fetchRouterList`. */
        readonly fetchRouterList?: RouterListFetcher;
      }
    | {
        /** Binds the provider to this enclave rather than the discovered router. */
        readonly enclave: TinfoilProviderEnclave;
        readonly userCacheSecret?: never;
        readonly fetchRouterList?: never;
      }
  );

/** The AI SDK provider, with the attested client its requests go through. */
export interface TinfoilProvider extends OpenAICompatibleProvider {
  /**
   * The client requests go through. It verifies the service again when the
   * verification expires or its key changes, and is bound to that service.
   */
  readonly httpClient: EnclaveHTTPClient | RouterHTTPClient;
}

/** @internal Seams for tests: the attested clients' own, including the globals the runtime is identified by. */
export type TinfoilProviderSeams = RouterClientSeams & EnclaveClientSeams;

/**
 * The one credential the options carry, or a {@link ConfigurationError} when
 * there is none or more than one. A long-lived API key is refused where the
 * runtime isn't a server, with the same error the OpenAI clients give: a
 * page or a worker holds a `bearerToken` instead.
 */
function credentialOf(options: TinfoilProviderOptions, globals: RuntimeGlobals | undefined): string {
  const apiKey = options.apiKey ?? "";
  const bearerToken = options.bearerToken ?? "";
  if (apiKey !== "" && bearerToken !== "") throw new ConfigurationError("give either apiKey or bearerToken, not both");
  if (apiKey === "" && bearerToken === "") throw new ConfigurationError("a credential is required: apiKey on a server, or bearerToken in a browser");
  checkAPIKeyRuntime(apiKey, globals);
  return apiKey !== "" ? apiKey : bearerToken;
}

/** @internal The factory with its test seams; {@link createTinfoil} is this without them. */
export async function createTinfoilProvider(options: TinfoilProviderOptions, seams: TinfoilProviderSeams): Promise<TinfoilProvider> {
  // The credential is checked first, so a provider without one fails before any network I/O.
  const credential = credentialOf(options, seams.globals);
  if (options.apiPath !== undefined && options.apiPath !== "") validateAPIPath(options.apiPath);
  const clientOptions = {
    transport: options.transport,
    policy: options.policy,
    verificationCheck: options.verificationCheck,
    fetchAttestation: options.fetchAttestation,
    signal: options.signal,
  };
  let client: EnclaveHTTPClient | RouterHTTPClient;
  if (options.enclave === undefined) {
    client = await createRouterHTTPClient({ ...clientOptions, userCacheSecret: options.userCacheSecret, fetchRouterList: options.fetchRouterList }, seams);
  } else {
    if (typeof options.enclave !== "object" || options.enclave === null) throw new ConfigurationError("enclave must be an object with a host and a trust");
    // Untyped code can give both; an enclave client has no cache secret to apply it to.
    const secret = (options as { readonly userCacheSecret?: unknown }).userCacheSecret;
    if ((options as { readonly fetchRouterList?: unknown }).fetchRouterList !== undefined) {
      throw new ConfigurationError("fetchRouterList is the router's option; an enclave client discovers no router");
    }
    if (secret !== undefined && secret !== "") {
      throw new ConfigurationError("userCacheSecret is the router's option; an enclave client never adds a user_cache_secret, so set it in each request body instead");
    }
    client = await createEnclaveHTTPClient(options.enclave.host, options.enclave.trust, clientOptions, seams);
  }
  const provider = createOpenAICompatible({
    name: "tinfoil",
    baseURL: apiBaseURL(client, options.apiPath),
    apiKey: credential,
    ...(options.headers === undefined ? {} : { headers: { ...options.headers } }),
    // The client's fetch has the global fetch's call signature, which is all a DOM or Node `typeof fetch` is. Bun's
    // typings merge a `preconnect` function onto the global, so under them a wrapped fetch is never `typeof fetch`.
    fetch: client.fetch as typeof globalThis.fetch,
    supportsStructuredOutputs: true,
  });
  // The provider is a function with the models' factories as properties; the client joins them as a fixed one.
  Object.defineProperty(provider, "httpClient", { value: client, writable: false, configurable: false, enumerable: true });
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
