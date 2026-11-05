/**
 * OpenAI clients over the attested HTTP clients. Each applies the caller's
 * OpenAI options first, then sets `fetch` and `baseURL` so the options can't
 * replace them, and keeps both fixed afterwards: the properties can't be
 * assigned, and a clone made with `withOptions` ignores `fetch` and `baseURL`
 * in the options it is given and keeps the attested transport. Per-request
 * `fetchOptions` are passed through to the attested `fetch` and can't bypass
 * it; only a separately constructed OpenAI client sends requests outside the
 * attested client's protections.
 */
import OpenAI, { type ClientOptions } from "openai";
import { createEnclaveHTTPClient, EnclaveHTTPClient, openAIURLOf, type EnclaveClientSeams } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import { createGatewayHTTPClient, GatewayHTTPClient, type GatewayClientSeams } from "./gateway-client.js";
import type { EnclaveOptions, GatewayOptions, RouterOptions } from "./options.js";
import { createRouterHTTPClient, RouterHTTPClient, type RouterClientSeams } from "./router-client.js";

/** The OpenAI options a client takes: everything but the transport it is bound to. */
export type OpenAIOptions = Omit<ClientOptions, "fetch" | "baseURL"> & {
  /**
   * A credential a browser page may hold, such as a short-lived token from
   * the application's own sign-in: sent as the API key, and allows browser
   * use without `dangerouslyAllowBrowser`. A long-lived API key belongs in
   * `apiKey` on a server, never in a page.
   */
  readonly bearerToken?: string;
};

/** The options as the OpenAI client takes them, with a bearer token applied. */
function openAIClientOptions(options: OpenAIOptions): Omit<ClientOptions, "fetch" | "baseURL"> {
  const { bearerToken, ...rest } = options;
  if (bearerToken === undefined || bearerToken === "") return rest;
  return { ...rest, apiKey: bearerToken, dangerouslyAllowBrowser: true };
}

/** The options each client was created with, which its clones inherit. */
const givenOptions = new WeakMap<OpenAI, OpenAIOptions>();

/** Fixes `fetch` and `baseURL` on a constructed client, so neither can be reassigned, and keeps the options it was given for its clones. */
function attest(client: OpenAI, fetchImpl: ClientOptions["fetch"], baseURL: string, options: OpenAIOptions): void {
  Object.defineProperty(client, "fetch", { value: fetchImpl, writable: false, configurable: false, enumerable: true });
  Object.defineProperty(client, "baseURL", { value: baseURL, writable: false, configurable: false, enumerable: true });
  givenOptions.set(client, { ...options });
}

/**
 * The options a clone is created with: the client's own, with `options` over
 * them, and never a transport. A credential given to the clone replaces the
 * inherited one whichever form it takes: `apiKey` clears an inherited
 * `bearerToken`, and `bearerToken` clears an inherited `apiKey`.
 */
function inherit(client: OpenAI, options: Partial<OpenAIOptions> & Partial<ClientOptions>): OpenAIOptions {
  const merged: Partial<ClientOptions> & { bearerToken?: string } = { ...givenOptions.get(client), ...options };
  delete merged.fetch;
  delete merged.baseURL;
  if ("apiKey" in options && !("bearerToken" in options)) delete merged.bearerToken;
  if ("bearerToken" in options && !("apiKey" in options)) delete merged.apiKey;
  return merged;
}

/** Marks construction by this module's factories; the constructors refuse anything else. */
const TOKEN = Symbol("OpenAIClient");

/**
 * An OpenAI client for Tinfoil's recommended route: the discovered router,
 * verified before the client is returned. Its `baseURL` is the URL requests
 * go to on that route.
 */
export class TinfoilClient extends OpenAI {
  readonly #httpClient: RouterHTTPClient;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, httpClient: RouterHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("TinfoilClient is created with createClient");
    super({ ...openAIClientOptions(options), fetch: httpClient.fetch, baseURL: openAIURLOf(httpClient) });
    this.#httpClient = httpClient;
    attest(this, httpClient.fetch, openAIURLOf(httpClient), options);
  }

  /** A client with `options` applied over this one's, on the same attested transport. */
  override withOptions(options: Partial<ClientOptions> & Partial<OpenAIOptions>): this {
    return new TinfoilClient(TOKEN, this.#httpClient, inherit(this, options)) as this;
  }

  /** A client for the recommended route, verified before it returns. */
  static create(options?: OpenAIOptions): Promise<TinfoilClient> {
    return createTinfoilClient(options ?? {}, {});
  }

  /**
   * The HTTP client requests go through. It verifies the service behind the
   * route again when the verification expires or its key changes, and is
   * bound to that service. A request's body and the response to it are
   * protected end to end; don't rely on headers, or a request without a body,
   * being private.
   */
  httpClient(): RouterHTTPClient {
    return this.#httpClient;
  }
}

/**
 * The recommended-route factory with its test seams; {@link createClient} is
 * this with the default router options and no seams.
 */
export async function createTinfoilClient(openaiOptions: OpenAIOptions, seams: RouterClientSeams, routerOptions: RouterOptions = {}): Promise<TinfoilClient> {
  const httpClient = await createRouterHTTPClient(routerOptions, seams);
  return new TinfoilClient(TOKEN, httpClient, openaiOptions);
}

/** A client for Tinfoil's recommended route, verified before it returns. */
export function createClient(options?: OpenAIOptions): Promise<TinfoilClient> {
  return TinfoilClient.create(options);
}

/**
 * An OpenAI client whose requests go through an {@link EnclaveHTTPClient},
 * to the `baseURL` option or, when that is unset, the enclave's `/v1/` API.
 */
/** The enclave OpenAI factory with its test seams; {@link EnclaveOpenAIClient.create} is this without them. */
export async function createEnclaveOpenAIClient(
  host: string,
  repo: string,
  options: EnclaveOptions,
  openaiOptions: OpenAIOptions,
  seams: EnclaveClientSeams,
): Promise<EnclaveOpenAIClient> {
  const httpClient = await createEnclaveHTTPClient(host, repo, options, seams);
  return new EnclaveOpenAIClient(TOKEN, httpClient, openaiOptions);
}

export class EnclaveOpenAIClient extends OpenAI {
  readonly #httpClient: EnclaveHTTPClient;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, httpClient: EnclaveHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("EnclaveOpenAIClient is created with EnclaveOpenAIClient.create");
    // The transport and base URL come last, so the caller's options can't replace them.
    super({ ...openAIClientOptions(options), fetch: httpClient.fetch, baseURL: openAIURLOf(httpClient) });
    this.#httpClient = httpClient;
    attest(this, httpClient.fetch, openAIURLOf(httpClient), options);
  }

  /** A client with `options` applied over this one's, on the same attested transport. */
  override withOptions(options: Partial<ClientOptions> & Partial<OpenAIOptions>): this {
    return new EnclaveOpenAIClient(TOKEN, this.#httpClient, inherit(this, options)) as this;
  }

  /** Creates an enclave client as {@link EnclaveHTTPClient.create} does, and an OpenAI client over it. */
  static create(host: string, repo: string, options?: EnclaveOptions, openaiOptions?: OpenAIOptions): Promise<EnclaveOpenAIClient> {
    return createEnclaveOpenAIClient(host, repo, options ?? {}, openaiOptions ?? {}, {});
  }

  /** The enclave client requests go through. */
  httpClient(): EnclaveHTTPClient {
    return this.#httpClient;
  }
}

/**
 * An OpenAI client whose requests go through a {@link RouterHTTPClient}, to
 * the `baseURL` option or, when that is unset, the router's `/v1/` API.
 */
/** The router OpenAI factory with its test seams; {@link RouterOpenAIClient.create} is this without them. */
export async function createRouterOpenAIClient(options: RouterOptions, openaiOptions: OpenAIOptions, seams: RouterClientSeams): Promise<RouterOpenAIClient> {
  const httpClient = await createRouterHTTPClient(options, seams);
  return new RouterOpenAIClient(TOKEN, httpClient, openaiOptions);
}

export class RouterOpenAIClient extends OpenAI {
  readonly #httpClient: RouterHTTPClient;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, httpClient: RouterHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("RouterOpenAIClient is created with RouterOpenAIClient.create");
    super({ ...openAIClientOptions(options), fetch: httpClient.fetch, baseURL: openAIURLOf(httpClient) });
    this.#httpClient = httpClient;
    attest(this, httpClient.fetch, openAIURLOf(httpClient), options);
  }

  /** A client with `options` applied over this one's, on the same attested transport. */
  override withOptions(options: Partial<ClientOptions> & Partial<OpenAIOptions>): this {
    return new RouterOpenAIClient(TOKEN, this.#httpClient, inherit(this, options)) as this;
  }

  /** Creates a router client as {@link RouterHTTPClient.create} does, and an OpenAI client over it. */
  static create(options?: RouterOptions, openaiOptions?: OpenAIOptions): Promise<RouterOpenAIClient> {
    return createRouterOpenAIClient(options ?? {}, openaiOptions ?? {}, {});
  }

  /** The router client requests go through. */
  httpClient(): RouterHTTPClient {
    return this.#httpClient;
  }
}

/**
 * The gateway OpenAI factory with its test seams; {@link GatewayOpenAIClient.create} is this without them.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export async function createGatewayOpenAIClient(options: GatewayOptions, openaiOptions: OpenAIOptions, seams: GatewayClientSeams): Promise<GatewayOpenAIClient> {
  const httpClient = await createGatewayHTTPClient(options, seams);
  return new GatewayOpenAIClient(TOKEN, httpClient, openaiOptions);
}

/**
 * An OpenAI client whose requests go through a {@link GatewayHTTPClient}, to
 * the gateway's URL.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export class GatewayOpenAIClient extends OpenAI {
  readonly #httpClient: GatewayHTTPClient;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, httpClient: GatewayHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("GatewayOpenAIClient is created with GatewayOpenAIClient.create");
    super({ ...openAIClientOptions(options), fetch: httpClient.fetch, baseURL: httpClient.baseURL() });
    this.#httpClient = httpClient;
    attest(this, httpClient.fetch, httpClient.baseURL(), options);
  }

  /** A client with `options` applied over this one's, on the same attested transport. */
  override withOptions(options: Partial<ClientOptions> & Partial<OpenAIOptions>): this {
    return new GatewayOpenAIClient(TOKEN, this.#httpClient, inherit(this, options)) as this;
  }

  /** Creates a gateway client as {@link GatewayHTTPClient.create} does, and an OpenAI client over it. */
  static create(options?: GatewayOptions, openaiOptions?: OpenAIOptions): Promise<GatewayOpenAIClient> {
    return createGatewayOpenAIClient(options ?? {}, openaiOptions ?? {}, {});
  }

  /** The gateway client requests go through. */
  httpClient(): GatewayHTTPClient {
    return this.#httpClient;
  }
}
