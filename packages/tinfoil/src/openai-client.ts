/**
 * OpenAI clients over the attested HTTP clients. Each applies the caller's
 * OpenAI options first, then sets `fetch` and `baseURL` so the options can't
 * replace them, and keeps both fixed afterwards, with `httpClient` beside
 * them: the properties can't be assigned, and `withOptions` doesn't take
 * `fetch` or `baseURL` (a clone ignores one passed from untyped code) and
 * keeps the attested transport. The OpenAI options that would choose another
 * transport or base URL (`dataResidency`, `provider`, `workloadIdentity`,
 * `credential` and `x509Transport`) are refused, by the factories before any
 * network I/O and by `withOptions`. Per-request `fetchOptions` are passed through to the
 * attested `fetch` and can't bypass it.
 *
 * Two things send outside the attested client's protections: a separately
 * constructed OpenAI client, and the openai package's WebSocket classes
 * (`ResponsesWS`, `LiveWS` and its sideband and forks, `OpenAIRealtimeWS`,
 * `OpenAIRealtimeWebSocket` and `OpenAIRealtimeTranslationWS`). Given one of
 * these clients, those classes open their own WebSocket to its base URL with
 * its credential, without the TLS pin, and nothing here can stop them. With
 * an enclave or router client, `createRealtimeWebSocket` replaces
 * `OpenAIRealtimeWS`, and `createWebSocket` opens a raw pinned WebSocket; both
 * always connect to the verified enclave. The other `ws`-based classes need
 * the settings from `pinnedWebSocketOptions(client.httpClient)`, and they are
 * pinned only when the client has no `baseURL` option, so that they connect
 * to the enclave itself over `wss://`. Behind a proxy `baseURL` the pinned
 * handshake fails, and over an `http://` one there is no TLS to pin.
 * `OpenAIRealtimeWebSocket` can't be pinned, and the gateway client has no
 * pinned WebSocket, so don't give it to those classes at all.
 *
 * The HTTP client owns the lifecycle: `httpClient.close()` releases it, and
 * an `await using` of the OpenAI client does the same, for its clones too,
 * since they share the transport.
 */
import OpenAI, { type ClientOptions } from "openai";
import { createEnclaveHTTPClient, EnclaveHTTPClient, openAIURLOf, type EnclaveClientSeams } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import { createGatewayHTTPClient, GatewayHTTPClient, type GatewayClientSeams } from "./gateway-client.js";
import { checkAPIKeyRuntime, registerCredential, type CredentialResolver } from "./internal/credential.js";
import { asyncDispose } from "./internal/dispose.js";
import type { RuntimeGlobals } from "./internal/platform.js";
import type { EnclaveOptions, GatewayOptions, Pin, RouterOptions } from "./options.js";
import { createRouterHTTPClient, RouterHTTPClient, type RouterClientSeams } from "./router-client.js";

/**
 * The OpenAI options that would route requests away from the attested
 * transport: a data residency or a third-party provider picks a base URL
 * over the client's, and the workload identity options authenticate through
 * OpenAI's own token exchange or certificate transport. The OpenAI client
 * refuses each of them alongside Tinfoil's `baseURL`, `apiKey` or `fetch`
 * today, but they are refused here too, so that the guarantee doesn't depend
 * on those checks. `OpenAIOptions` omits the same keys.
 */
const FORBIDDEN_TRANSPORT_OPTIONS = ["dataResidency", "provider", "workloadIdentity", "credential", "x509Transport"] as const satisfies readonly (keyof ClientOptions)[];

/**
 * The OpenAI options a client takes: everything but the transport it is
 * bound to and the options that would choose another one (`dataResidency`,
 * `provider`, `workloadIdentity`, `credential` and `x509Transport`), which
 * are a {@link ConfigurationError} when untyped code passes one. An `apiKey`
 * is accepted only where the runtime is a server (Node or Bun); anywhere
 * else, `dangerouslyAllowBrowser` included, it is a
 * {@link ConfigurationError} naming `bearerToken` as the credential to give.
 */
export type OpenAIOptions = Omit<ClientOptions, "fetch" | "baseURL" | "dataResidency" | "provider" | "workloadIdentity" | "credential" | "x509Transport"> & {
  /**
   * A credential a browser page may hold, such as a short-lived token from
   * the application's own sign-in: sent as the API key, and allows browser
   * use without `dangerouslyAllowBrowser`. A long-lived API key belongs in
   * `apiKey` on a server, never in a page.
   */
  readonly bearerToken?: string;
};

/**
 * Refuses an option in {@link FORBIDDEN_TRANSPORT_OPTIONS} that the caller set, which
 * untyped code can pass whatever the type says. An option the caller holds
 * as `undefined` or `null` is unset and passes; {@link openAIClientOptions}
 * then drops it, so that the OpenAI client never sees it. One that the
 * options only inherit passes too, since a spread doesn't copy it.
 */
function refuseTransportOptions(options: object): void {
  for (const key of FORBIDDEN_TRANSPORT_OPTIONS) {
    if (Object.prototype.hasOwnProperty.call(options, key) && (options as Record<string, unknown>)[key] != null) {
      throw new ConfigurationError(`the ${key} option is not supported: the Tinfoil client owns the transport and base URL that requests go to`);
    }
  }
}

/**
 * Checks the OpenAI options a factory is given before any network I/O: the
 * options that would choose another transport, and an `apiKey` outside a
 * server.
 */
function checkOpenAIOptions(options: OpenAIOptions, globals: RuntimeGlobals | undefined): void {
  refuseTransportOptions(options);
  checkAPIKeyRuntime(options.apiKey, globals);
}

/**
 * The options as the OpenAI client takes them, with a bearer token applied.
 * The options that would choose another transport, and an `apiKey` outside a
 * server, are refused here too, so that every constructor, and a clone made
 * with `withOptions`, applies the rules as the factories do.
 */
function openAIClientOptions(options: OpenAIOptions): Omit<ClientOptions, "fetch" | "baseURL"> {
  refuseTransportOptions(options);
  const { bearerToken, ...given } = options;
  // What is left of these options is unset; the OpenAI client takes most of
  // them as unset but refuses a null `credential`, so none of them reach it.
  const rest: Omit<ClientOptions, "fetch" | "baseURL"> = { ...given };
  for (const key of FORBIDDEN_TRANSPORT_OPTIONS) delete (rest as Record<string, unknown>)[key];
  checkAPIKeyRuntime(rest.apiKey);
  if (bearerToken === undefined || bearerToken === "") return rest;
  return { ...rest, apiKey: bearerToken, dangerouslyAllowBrowser: true };
}

/** The options each client was created with, which its clones inherit. */
const givenOptions = new WeakMap<OpenAI, OpenAIOptions>();

/** The attested HTTP client an OpenAI client sends through. */
type AttestedHTTPClient = EnclaveHTTPClient | RouterHTTPClient | GatewayHTTPClient;

/**
 * How a connection the client doesn't send through its request loop, such
 * as a realtime session, gets the client's credential: an `apiKey` given as
 * a function is called when the connection is opened, as it is for a
 * request, and must return a non-empty string; otherwise the key the client
 * holds, a bearer token or an `apiKey` string, or `null` when it has neither.
 */
function credentialResolver(client: OpenAI, apiKey: ClientOptions["apiKey"]): CredentialResolver {
  if (typeof apiKey !== "function") return () => client.apiKey;
  return async () => {
    const token = await apiKey();
    if (typeof token !== "string" || token === "") throw new ConfigurationError(`the apiKey function must return a non-empty string, got ${typeof token}`);
    return token;
  };
}

/**
 * Fixes `fetch`, `baseURL` and `httpClient` on a constructed client, so none
 * can be reassigned, keeps the options it was given for its clones, and
 * records how it resolves its credential (`apiKey` as the options applied
 * it) for connections opened outside its request loop. The OpenAI
 * constructor sets `fetch` and `baseURL` as plain properties, so they are
 * redefined here rather than declared as fields.
 */
function attest(client: OpenAI, httpClient: AttestedHTTPClient, baseURL: string, options: OpenAIOptions, apiKey: ClientOptions["apiKey"]): void {
  const fixed = { writable: false, configurable: false, enumerable: true };
  Object.defineProperty(client, "fetch", { ...fixed, value: httpClient.fetch });
  Object.defineProperty(client, "baseURL", { ...fixed, value: baseURL });
  Object.defineProperty(client, "httpClient", { ...fixed, value: httpClient });
  givenOptions.set(client, { ...options });
  registerCredential(client, credentialResolver(client, apiKey));
}

/**
 * The options a clone is created with: the client's own, with `options` over
 * them, and never a transport. The parameter type has no `fetch` or
 * `baseURL`; one passed from untyped code is dropped here all the same. A
 * credential given to the clone replaces the inherited one whichever form it
 * takes: `apiKey` clears an inherited `bearerToken`, and `bearerToken`
 * clears an inherited `apiKey`.
 */
function inherit(client: OpenAI, options: Partial<OpenAIOptions>): OpenAIOptions {
  const merged: Partial<ClientOptions> & { bearerToken?: string } = { ...givenOptions.get(client), ...options };
  delete merged.fetch;
  delete merged.baseURL;
  if ("apiKey" in options && !("bearerToken" in options)) delete merged.bearerToken;
  if ("bearerToken" in options && !("apiKey" in options)) delete merged.apiKey;
  return merged;
}

/** Only this module holds the token the constructors require, so untyped code that calls one is refused. */
const TOKEN: unique symbol = Symbol("OpenAIClient");

/**
 * Call the private constructors; each class assigns its own, as the only
 * place its constructor can be called by type-checked code, so a client
 * over an attested transport comes from a factory and nothing else.
 */
let constructTinfoil: (httpClient: RouterHTTPClient, options: OpenAIOptions) => TinfoilClient;
let constructEnclave: (httpClient: EnclaveHTTPClient, options: OpenAIOptions) => EnclaveOpenAIClient;
let constructRouter: (httpClient: RouterHTTPClient, options: OpenAIOptions) => RouterOpenAIClient;
let constructGateway: (httpClient: GatewayHTTPClient, options: OpenAIOptions) => GatewayOpenAIClient;

/**
 * An OpenAI client for Tinfoil's recommended route: the discovered router,
 * verified before the client is returned. Its `baseURL` is the URL requests
 * go to on that route. Created only by {@link createClient} or
 * {@link TinfoilClient.create}: the constructor is private, as it is on
 * every client below, so type-checked code cannot call it, and a call from
 * untyped code is refused at runtime.
 *
 * Errors: the factory rejects with the client's own errors
 * ({@link ConfigurationError}, {@link NetworkError}, {@link AttestationError}).
 * A call through the OpenAI API surface, such as
 * `chat.completions.create(...)`, goes through the OpenAI client's request
 * loop, which catches whatever the attested `fetch` throws, retries the
 * request `maxRetries` times (2 by default; a request whose body is a
 * stream isn't retried) and then throws `APIConnectionError` with the
 * client's error as its `cause`. An enclave that fails to verify again on a
 * request thus surfaces as an `APIConnectionError` caused by an
 * {@link AttestationError}, after three verification attempts; `maxRetries:
 * 0` on the client or the request shows the first failure.
 */
export class TinfoilClient extends OpenAI {
  /**
   * The HTTP client requests go through. It verifies the service behind the
   * route again when the verification expires or its key changes, and is
   * bound to that service. A request's body and the response to it are
   * protected end to end; don't rely on headers, or a request without a body,
   * being private.
   */
  declare readonly httpClient: RouterHTTPClient;

  private constructor(token: typeof TOKEN, httpClient: RouterHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("TinfoilClient is created with createClient");
    const clientOptions = openAIClientOptions(options);
    super({ ...clientOptions, fetch: httpClient.fetch, baseURL: openAIURLOf(httpClient) });
    attest(this, httpClient, openAIURLOf(httpClient), options, clientOptions.apiKey);
  }

  static {
    constructTinfoil = (httpClient, options) => new TinfoilClient(TOKEN, httpClient, options);
  }

  /**
   * A client with `options` applied over this one's, on the same attested
   * transport. `fetch` and `baseURL` aren't options here: the transport owns
   * them, and one passed from untyped code is ignored. An option that would
   * choose another transport, such as `provider`, is a {@link ConfigurationError}.
   */
  override withOptions(options: Partial<OpenAIOptions>): this {
    return new TinfoilClient(TOKEN, this.httpClient, inherit(this, options)) as this;
  }

  /** Closes `httpClient` at the end of an `await using` block; see {@link RouterHTTPClient.close}. */
  [asyncDispose](): Promise<void> {
    return this.httpClient.close();
  }

  /** A client for the recommended route, verified before it returns. */
  static create(options?: OpenAIOptions): Promise<TinfoilClient> {
    return createTinfoilClient(options ?? {}, {});
  }
}

/**
 * @internal The recommended-route factory with its test seams;
 * {@link createClient} is this with the default router options and no seams.
 */
export async function createTinfoilClient(openaiOptions: OpenAIOptions, seams: RouterClientSeams, routerOptions: RouterOptions = {}): Promise<TinfoilClient> {
  // The OpenAI options are checked first, so a client with the wrong ones fails before any network I/O.
  checkOpenAIOptions(openaiOptions, seams.globals);
  const httpClient = await createRouterHTTPClient(routerOptions, seams);
  return constructTinfoil(httpClient, openaiOptions);
}

/** A client for Tinfoil's recommended route, verified before it returns. */
export function createClient(options?: OpenAIOptions): Promise<TinfoilClient> {
  return TinfoilClient.create(options);
}

/** @internal The enclave OpenAI factory with its test seams; {@link EnclaveOpenAIClient.create} is this without them. */
export async function createEnclaveOpenAIClient(
  host: string,
  pin: Pin,
  options: EnclaveOptions,
  openaiOptions: OpenAIOptions,
  seams: EnclaveClientSeams,
): Promise<EnclaveOpenAIClient> {
  checkOpenAIOptions(openaiOptions, seams.globals);
  const httpClient = await createEnclaveHTTPClient(host, pin, options, seams);
  return constructEnclave(httpClient, openaiOptions);
}

/**
 * An OpenAI client whose requests go through an {@link EnclaveHTTPClient},
 * to the `baseURL` option or, when that is unset, the enclave's `/v1/` API.
 * Errors surface as for {@link TinfoilClient}.
 */
export class EnclaveOpenAIClient extends OpenAI {
  /** The enclave client requests go through. */
  declare readonly httpClient: EnclaveHTTPClient;

  private constructor(token: typeof TOKEN, httpClient: EnclaveHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("EnclaveOpenAIClient is created with EnclaveOpenAIClient.create");
    // The transport and base URL come last, so the caller's options can't replace them.
    const clientOptions = openAIClientOptions(options);
    super({ ...clientOptions, fetch: httpClient.fetch, baseURL: openAIURLOf(httpClient) });
    attest(this, httpClient, openAIURLOf(httpClient), options, clientOptions.apiKey);
  }

  static {
    constructEnclave = (httpClient, options) => new EnclaveOpenAIClient(TOKEN, httpClient, options);
  }

  /**
   * A client with `options` applied over this one's, on the same attested
   * transport. `fetch` and `baseURL` aren't options here: the transport owns
   * them, and one passed from untyped code is ignored. An option that would
   * choose another transport, such as `provider`, is a {@link ConfigurationError}.
   */
  override withOptions(options: Partial<OpenAIOptions>): this {
    return new EnclaveOpenAIClient(TOKEN, this.httpClient, inherit(this, options)) as this;
  }

  /** Closes `httpClient` at the end of an `await using` block; see {@link EnclaveHTTPClient.close}. */
  [asyncDispose](): Promise<void> {
    return this.httpClient.close();
  }

  /** Creates an enclave client as {@link EnclaveHTTPClient.create} does, and an OpenAI client over it. */
  static create(host: string, pin: Pin, options?: EnclaveOptions, openaiOptions?: OpenAIOptions): Promise<EnclaveOpenAIClient> {
    return createEnclaveOpenAIClient(host, pin, options ?? {}, openaiOptions ?? {}, {});
  }
}

/** @internal The router OpenAI factory with its test seams; {@link RouterOpenAIClient.create} is this without them. */
export async function createRouterOpenAIClient(options: RouterOptions, openaiOptions: OpenAIOptions, seams: RouterClientSeams): Promise<RouterOpenAIClient> {
  checkOpenAIOptions(openaiOptions, seams.globals);
  const httpClient = await createRouterHTTPClient(options, seams);
  return constructRouter(httpClient, openaiOptions);
}

/**
 * An OpenAI client whose requests go through a {@link RouterHTTPClient}, to
 * the `baseURL` option or, when that is unset, the router's `/v1/` API.
 * Errors surface as for {@link TinfoilClient}.
 */
export class RouterOpenAIClient extends OpenAI {
  /** The router client requests go through. */
  declare readonly httpClient: RouterHTTPClient;

  private constructor(token: typeof TOKEN, httpClient: RouterHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("RouterOpenAIClient is created with RouterOpenAIClient.create");
    const clientOptions = openAIClientOptions(options);
    super({ ...clientOptions, fetch: httpClient.fetch, baseURL: openAIURLOf(httpClient) });
    attest(this, httpClient, openAIURLOf(httpClient), options, clientOptions.apiKey);
  }

  static {
    constructRouter = (httpClient, options) => new RouterOpenAIClient(TOKEN, httpClient, options);
  }

  /**
   * A client with `options` applied over this one's, on the same attested
   * transport. `fetch` and `baseURL` aren't options here: the transport owns
   * them, and one passed from untyped code is ignored. An option that would
   * choose another transport, such as `provider`, is a {@link ConfigurationError}.
   */
  override withOptions(options: Partial<OpenAIOptions>): this {
    return new RouterOpenAIClient(TOKEN, this.httpClient, inherit(this, options)) as this;
  }

  /** Closes `httpClient` at the end of an `await using` block; see {@link RouterHTTPClient.close}. */
  [asyncDispose](): Promise<void> {
    return this.httpClient.close();
  }

  /** Creates a router client as {@link RouterHTTPClient.create} does, and an OpenAI client over it. */
  static create(options?: RouterOptions, openaiOptions?: OpenAIOptions): Promise<RouterOpenAIClient> {
    return createRouterOpenAIClient(options ?? {}, openaiOptions ?? {}, {});
  }
}

/** @internal The gateway OpenAI factory with its test seams; {@link GatewayOpenAIClient.create} is this without them. */
export async function createGatewayOpenAIClient(options: GatewayOptions, openaiOptions: OpenAIOptions, seams: GatewayClientSeams): Promise<GatewayOpenAIClient> {
  checkOpenAIOptions(openaiOptions, seams.globals);
  const httpClient = await createGatewayHTTPClient(options, seams);
  return constructGateway(httpClient, openaiOptions);
}

/**
 * An OpenAI client whose requests go through a {@link GatewayHTTPClient}, to
 * the gateway's URL. Errors surface as for {@link TinfoilClient}.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export class GatewayOpenAIClient extends OpenAI {
  /** The gateway client requests go through. */
  declare readonly httpClient: GatewayHTTPClient;

  private constructor(token: typeof TOKEN, httpClient: GatewayHTTPClient, options: OpenAIOptions) {
    if (token !== TOKEN) throw new ConfigurationError("GatewayOpenAIClient is created with GatewayOpenAIClient.create");
    const clientOptions = openAIClientOptions(options);
    super({ ...clientOptions, fetch: httpClient.fetch, baseURL: httpClient.baseURL });
    attest(this, httpClient, httpClient.baseURL, options, clientOptions.apiKey);
  }

  static {
    constructGateway = (httpClient, options) => new GatewayOpenAIClient(TOKEN, httpClient, options);
  }

  /**
   * A client with `options` applied over this one's, on the same attested
   * transport. `fetch` and `baseURL` aren't options here: the transport owns
   * them, and one passed from untyped code is ignored. An option that would
   * choose another transport, such as `provider`, is a {@link ConfigurationError}.
   */
  override withOptions(options: Partial<OpenAIOptions>): this {
    return new GatewayOpenAIClient(TOKEN, this.httpClient, inherit(this, options)) as this;
  }

  /** Closes `httpClient` at the end of an `await using` block; see {@link GatewayHTTPClient.close}. */
  [asyncDispose](): Promise<void> {
    return this.httpClient.close();
  }

  /** Creates a gateway client as {@link GatewayHTTPClient.create} does, and an OpenAI client over it. */
  static create(options?: GatewayOptions, openaiOptions?: OpenAIOptions): Promise<GatewayOpenAIClient> {
    return createGatewayOpenAIClient(options ?? {}, openaiOptions ?? {}, {});
  }
}
