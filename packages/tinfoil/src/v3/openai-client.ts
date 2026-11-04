/**
 * OpenAI clients over the attested HTTP clients. Each applies the caller's
 * OpenAI options first, then sets `fetch` and `baseURL` so the options can't
 * replace them. Per-request `fetchOptions` are passed through to the attested
 * `fetch` and can't bypass it; only a separately constructed OpenAI client
 * sends requests outside the attested client's protections.
 */
import OpenAI, { type ClientOptions } from "openai";
import { EnclaveHTTPClient } from "./enclave-client.js";
import { GatewayHTTPClient } from "./gateway-client.js";
import { notImplemented } from "./internal/not-implemented.js";
import type { EnclaveOptions, GatewayOptions, RouterOptions } from "./options.js";
import { RouterHTTPClient } from "./router-client.js";

/** The OpenAI options a client takes: everything but the transport it is bound to. */
export type OpenAIOptions = Omit<ClientOptions, "fetch" | "baseURL">;

/**
 * An OpenAI client for Tinfoil's recommended route: the discovered router,
 * verified before the client is returned. Its `baseURL` is the URL requests
 * go to on that route.
 */
export class TinfoilClient extends OpenAI {
  readonly #httpClient: RouterHTTPClient;

  private constructor(httpClient: RouterHTTPClient, options: OpenAIOptions) {
    super({ ...options, fetch: httpClient.fetch, baseURL: notImplemented("TinfoilClient.baseURL") });
    this.#httpClient = httpClient;
  }

  /** A client for the recommended route, verified before it returns. */
  static async create(options?: OpenAIOptions): Promise<TinfoilClient> {
    void options;
    return notImplemented("TinfoilClient.create");
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

/** A client for Tinfoil's recommended route, verified before it returns. */
export function createClient(options?: OpenAIOptions): Promise<TinfoilClient> {
  return TinfoilClient.create(options);
}

/**
 * An OpenAI client whose requests go through an {@link EnclaveHTTPClient},
 * to the `baseURL` option or, when that is unset, the enclave's `/v1/` API.
 */
export class EnclaveOpenAIClient extends OpenAI {
  readonly #httpClient: EnclaveHTTPClient;

  private constructor(httpClient: EnclaveHTTPClient, options: OpenAIOptions) {
    super({ ...options, fetch: httpClient.fetch, baseURL: notImplemented("EnclaveOpenAIClient.baseURL") });
    this.#httpClient = httpClient;
  }

  /** Creates an enclave client as {@link EnclaveHTTPClient.create} does, and an OpenAI client over it. */
  static async create(host: string, repo: string, options?: EnclaveOptions, openaiOptions?: OpenAIOptions): Promise<EnclaveOpenAIClient> {
    void host;
    void repo;
    void options;
    void openaiOptions;
    return notImplemented("EnclaveOpenAIClient.create");
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
export class RouterOpenAIClient extends OpenAI {
  readonly #httpClient: RouterHTTPClient;

  private constructor(httpClient: RouterHTTPClient, options: OpenAIOptions) {
    super({ ...options, fetch: httpClient.fetch, baseURL: notImplemented("RouterOpenAIClient.baseURL") });
    this.#httpClient = httpClient;
  }

  /** Creates a router client as {@link RouterHTTPClient.create} does, and an OpenAI client over it. */
  static async create(options?: RouterOptions, openaiOptions?: OpenAIOptions): Promise<RouterOpenAIClient> {
    void options;
    void openaiOptions;
    return notImplemented("RouterOpenAIClient.create");
  }

  /** The router client requests go through. */
  httpClient(): RouterHTTPClient {
    return this.#httpClient;
  }
}

/**
 * An OpenAI client whose requests go through a {@link GatewayHTTPClient}, to
 * the gateway's URL.
 *
 * Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.
 */
export class GatewayOpenAIClient extends OpenAI {
  readonly #httpClient: GatewayHTTPClient;

  private constructor(httpClient: GatewayHTTPClient, options: OpenAIOptions) {
    super({ ...options, fetch: httpClient.fetch, baseURL: httpClient.baseURL() });
    this.#httpClient = httpClient;
  }

  /** Creates a gateway client as {@link GatewayHTTPClient.create} does, and an OpenAI client over it. */
  static async create(options?: GatewayOptions, openaiOptions?: OpenAIOptions): Promise<GatewayOpenAIClient> {
    void options;
    void openaiOptions;
    return notImplemented("GatewayOpenAIClient.create");
  }

  /** The gateway client requests go through. */
  httpClient(): GatewayHTTPClient {
    return this.#httpClient;
  }
}
