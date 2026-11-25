/**
 * The OpenAI-compatible client over the attested HTTP clients. One class,
 * {@link OpenAIClient}, takes any of the SDK's three HTTP clients, sends
 * through its attested `fetch`, and sets the OpenAI client's base URL
 * itself: the API path joined under the HTTP client's EHBP proxy or the
 * enclave's origin, or under the gateway's URL. It applies the caller's
 * OpenAI options first, then sets `fetch` and `baseURL` so that the options
 * can't replace them, and keeps both fixed afterwards, with `httpClient`
 * beside them: the properties can't be assigned, and `withOptions` doesn't
 * take `fetch` or `baseURL` (a clone ignores one passed from untyped code)
 * and keeps the attested transport. A base URL that the caller sets through
 * the OpenAI options, through `OPENAI_BASE_URL` in the environment, or
 * through `dataResidency` has no effect; the `apiPath` option chooses the
 * API path, and is taken out of the options before the rest reach the
 * OpenAI client. The
 * OpenAI options that would choose another transport (`provider`,
 * `workloadIdentity`, `credential` and `x509Transport`) are refused, before
 * any network I/O and by `withOptions`. Per-request `fetchOptions` are
 * passed through to the attested `fetch` and can't bypass it.
 *
 * A separately constructed OpenAI client sends outside the attested
 * client's protections. So would the openai package's WebSocket classes
 * (`ResponsesWS`, `LiveWS` and its sideband and forks, `OpenAIRealtimeWS`,
 * `OpenAIRealtimeWebSocket` and `OpenAIRealtimeTranslationWS`, stable and
 * beta), which open their own WebSocket to the client's base URL with its
 * credential, without the TLS pin, so these clients refuse them with a
 * {@link ConfigurationError} before any connection is opened: see
 * {@link refuseOpenAIWebSockets}. With an enclave or router client,
 * `createRealtimeWebSocket` replaces `OpenAIRealtimeWS`, and
 * `createWebSocket` opens a raw pinned WebSocket; both always connect to the
 * verified enclave. On Node, the other `ws`-based classes can be given the
 * settings from `pinnedWebSocketOptions(client.httpClient)` together with a
 * plain OpenAI client whose base URL is the enclave itself, so that the
 * connection that they open is pinned. In a browser, no WebSocket can be
 * pinned, and the gateway client has no pinned WebSocket at all.
 *
 * The HTTP client owns the lifecycle: `httpClient.close()` releases it, and
 * an `await using` of the OpenAI client does the same, for its clones too,
 * since they share the transport.
 */
import OpenAI, { type ClientOptions } from "openai";
import type { EnclaveHTTPClient } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import type { GatewayHTTPClient } from "./gateway-client.js";
import { apiBaseURL, validateAPIPath } from "./internal/api-path.js";
import { checkAPIKeyRuntime, registerCredential, type CredentialResolver } from "./internal/credential.js";
import { asyncDispose } from "./internal/dispose.js";
import { isServerRuntime, type RuntimeGlobals } from "./internal/platform.js";
import type { RouterOptions } from "./options.js";
import { createRouterHTTPClient, type RouterClientSeams, type RouterHTTPClient } from "./router-client.js";

/**
 * The HTTP clients that an {@link OpenAIClient} can send through: an
 * {@link EnclaveHTTPClient}, a {@link RouterHTTPClient} or a
 * {@link GatewayHTTPClient} that its factory created. Anything else, such as
 * `null` or an object of the caller's own, is a {@link ConfigurationError}.
 */
export type AttestedHTTPClient = EnclaveHTTPClient | RouterHTTPClient | GatewayHTTPClient;

/**
 * The OpenAI options that would route requests away from the attested
 * transport: a third-party provider picks a base URL and authentication of
 * its own, and the workload identity options authenticate through OpenAI's
 * own token exchange or certificate transport. The OpenAI client refuses
 * each of them alongside Tinfoil's `baseURL`, `apiKey` or `fetch` today, but
 * they are refused here too, so that the guarantee doesn't depend on those
 * checks. `OpenAIClientOptions` omits the same keys.
 */
const FORBIDDEN_TRANSPORT_OPTIONS = ["provider", "workloadIdentity", "credential", "x509Transport"] as const satisfies readonly (keyof ClientOptions)[];

/**
 * The OpenAI options that choose the base URL, which the client sets
 * itself: they are dropped, so that they have no effect. The OpenAI client
 * would otherwise prefer a data residency's base URL to the one it is given.
 */
const IGNORED_BASE_URL_OPTIONS = ["baseURL", "dataResidency"] as const satisfies readonly (keyof ClientOptions)[];

/**
 * The options that an {@link OpenAIClient} takes: the OpenAI client's own
 * options, with `bearerToken` and `apiPath` beside them. They are everything
 * but the transport that the client is bound to, the base URL that it sets
 * itself (`baseURL` and `dataResidency`, which have no effect when untyped
 * code passes one), and the options that would choose another transport
 * (`provider`, `workloadIdentity`, `credential` and `x509Transport`), which
 * are a {@link ConfigurationError}. An `apiKey` is accepted only where the
 * runtime is a server (Node or Bun); anywhere else,
 * `dangerouslyAllowBrowser` included, it is a {@link ConfigurationError}
 * naming `bearerToken` as the credential to give.
 */
export type OpenAIClientOptions = Omit<ClientOptions, "fetch" | "baseURL" | "dataResidency" | "provider" | "workloadIdentity" | "credential" | "x509Transport"> & {
  /**
   * The path of the API, joined under the HTTP client's base URL: the EHBP
   * proxy or, when there is none, the enclave's origin, or the gateway's
   * URL. Leave it out for `/v1/`. It must be an absolute path (starting with
   * `/` but not `//`) of RFC 3986 path characters, without a query, a
   * fragment, an encoded slash or backslash, or a "." or ".." segment,
   * percent-encoded or not; anything else, the empty string included, is a
   * {@link ConfigurationError}. It configures the Tinfoil client and is not
   * passed to the OpenAI client.
   */
  readonly apiPath?: string;
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
 * Checks the options a factory is given before any network I/O: the
 * options that would choose another transport, an `apiKey` outside a
 * server, and the API path.
 */
function checkOpenAIOptions(options: OpenAIClientOptions, globals: RuntimeGlobals | undefined): void {
  refuseTransportOptions(options);
  checkAPIKeyRuntime(options.apiKey, globals);
  if (options.apiPath !== undefined) validateAPIPath(options.apiPath);
}

/**
 * The options as the OpenAI client takes them, with a bearer token applied.
 * The options that would choose another transport, and an `apiKey` outside a
 * server, are refused here too, so that every constructor, and a clone made
 * with `withOptions`, applies the rules as the factories do.
 */
function openAIClientOptions(options: OpenAIClientOptions): Omit<ClientOptions, "fetch" | "baseURL"> {
  refuseTransportOptions(options);
  const { bearerToken, ...given } = options;
  // What is left of these options is unset; the OpenAI client takes most of
  // them as unset but refuses a null `credential`, so none of them reach it.
  // The base URL options are dropped whatever their value, so they have no
  // effect, and the API path configures this client, not the OpenAI client.
  const rest: Omit<ClientOptions, "fetch" | "baseURL"> = { ...given };
  for (const key of [...FORBIDDEN_TRANSPORT_OPTIONS, ...IGNORED_BASE_URL_OPTIONS, "apiPath"]) delete (rest as Record<string, unknown>)[key];
  checkAPIKeyRuntime(rest.apiKey);
  if (bearerToken === undefined || bearerToken === "") return rest;
  return { ...rest, apiKey: bearerToken, dangerouslyAllowBrowser: true };
}

/** The options that each client was created with, `apiPath` included, which its clones inherit. */
const givenOptions = new WeakMap<OpenAI, OpenAIClientOptions>();

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

/** Why a client refuses the openai package's WebSocket classes, on a server. */
export const OPENAI_WEBSOCKETS_REFUSED =
  "the openai package's WebSocket classes (such as ResponsesWS, LiveWS and OpenAIRealtimeWS) can't be given a Tinfoil OpenAI client: they open their own WebSocket to the client's base URL, outside the attested transport and without the TLS pin. Use createRealtimeWebSocket from tinfoil/openai for a realtime session or createWebSocket from tinfoil for a pinned WebSocket; on Node, such a class can instead be given a plain OpenAI client whose base URL is the enclave, together with the settings from pinnedWebSocketOptions(client.httpClient)";

/** Why a client refuses the openai package's WebSocket classes, in a browser, where nothing can pin a WebSocket. */
export const OPENAI_WEBSOCKETS_REFUSED_IN_BROWSERS =
  "the openai package's WebSocket classes (such as OpenAIRealtimeWebSocket) can't be given a Tinfoil OpenAI client: they open their own WebSocket to the client's base URL, outside the attested transport, and a WebSocket can't be pinned to the attested key in a browser, which doesn't expose the server certificate to scripts";

/** Why a client can't be created over an openai release whose internals it can't use to refuse the WebSocket classes. */
export const UNSUPPORTED_OPENAI_RELEASE =
  "this release of the openai package lacks the internal members (_buildWebSocketHeaders, _callApiKey, _hasApiKeyProvider and _options.apiKey) through which a Tinfoil OpenAI client refuses the package's WebSocket classes, so the client can't be created over it; install a release that tinfoil supports";

function webSocketRefusal(): ConfigurationError {
  return new ConfigurationError(isServerRuntime() ? OPENAI_WEBSOCKETS_REFUSED : OPENAI_WEBSOCKETS_REFUSED_IN_BROWSERS);
}

/** The clients whose next read of their `_options.apiKey` is their own request path's: see {@link refuseOpenAIWebSockets}. */
const ownCredentialRead = new WeakSet<object>();

/** The client's `_options.apiKey`, read as its own request path reads it. */
function ownAPIKey(client: OpenAI): ClientOptions["apiKey"] {
  ownCredentialRead.add(client);
  try {
    return (client as unknown as { _options: ClientOptions })._options.apiKey;
  } finally {
    ownCredentialRead.delete(client);
  }
}

/**
 * Makes `client` refuse the openai package's WebSocket classes with a
 * {@link ConfigurationError}, before any connection is opened. The classes
 * take the socket's settings themselves and never show them to the client,
 * so the client can't tell a pinned connection from an unpinned one, and it
 * refuses every one; a pinned connection is opened through Tinfoil's own
 * WebSockets, or by a class that is given a plain OpenAI client.
 *
 * The classes reach the client through two of its internal members before
 * they connect. Each class that the package generates from its API
 * (`ResponsesWS`, `LiveWS` and its sideband and forks), and
 * `OpenAIRealtimeTranslationWS`, calls `_buildWebSocketHeaders` for the
 * headers of each handshake, its reconnections included, and nothing else
 * calls it: here it throws. A class that the package generates later calls
 * it as the others do, so it is refused too. The realtime classes
 * (`OpenAIRealtimeWS` and `OpenAIRealtimeWebSocket`, stable and beta) call
 * nothing on the client, but each of them reads `_options.apiKey` to learn
 * whether the credential is a function, a read that the client's own
 * requests make only through `_hasApiKeyProvider` and `_callApiKey`: the
 * option becomes a getter that throws, except for the one read that each
 * call of those methods makes.
 */
function refuseOpenAIWebSockets(client: OpenAI): void {
  // An openai release without these members would leave the classes unrefused, so it is refused instead.
  const internals = client as unknown as Record<string, unknown>;
  const options = internals._options as ClientOptions | undefined;
  if (typeof internals._buildWebSocketHeaders !== "function" || typeof internals._callApiKey !== "function" || typeof internals._hasApiKeyProvider !== "function" || typeof options !== "object" || options === null || !Object.prototype.hasOwnProperty.call(options, "apiKey")) {
    throw new ConfigurationError(UNSUPPORTED_OPENAI_RELEASE);
  }
  const fixed = { writable: false, configurable: false };
  Object.defineProperty(client, "_buildWebSocketHeaders", {
    ...fixed,
    enumerable: false,
    value: (): never => {
      throw webSocketRefusal();
    },
  });
  // The client's own request path reads the option through these two methods, each of them once, synchronously.
  const callApiKey = client._callApiKey;
  Object.defineProperty(client, "_hasApiKeyProvider", { ...fixed, enumerable: false, value: (): boolean => typeof ownAPIKey(client) === "function" });
  Object.defineProperty(client, "_callApiKey", {
    ...fixed,
    enumerable: false,
    value: (capture?: (apiKey: string | null) => void): Promise<boolean> => {
      ownCredentialRead.add(client);
      try {
        return callApiKey.call(client, capture);
      } finally {
        ownCredentialRead.delete(client);
      }
    },
  });
  const apiKey = options.apiKey;
  Object.defineProperty(options, "apiKey", {
    configurable: false,
    enumerable: false,
    get: () => {
      if (ownCredentialRead.delete(client)) return apiKey;
      throw webSocketRefusal();
    },
  });
  Object.defineProperty(client, "_options", { ...fixed, enumerable: true, value: options });
}

/**
 * Fixes `fetch`, `baseURL` and `httpClient` on a constructed client, so none
 * can be reassigned, keeps the options it was given for its clones, records
 * how it resolves its credential (`apiKey` as the options applied it) for
 * connections opened outside its request loop, and makes it refuse the
 * openai package's WebSocket classes. The OpenAI constructor sets `fetch`
 * and `baseURL` as plain properties, so they are redefined here rather than
 * declared as fields.
 */
function attest(client: OpenAI, httpClient: AttestedHTTPClient, baseURL: string, options: OpenAIClientOptions, apiKey: ClientOptions["apiKey"]): void {
  const fixed = { writable: false, configurable: false, enumerable: true };
  Object.defineProperty(client, "fetch", { ...fixed, value: httpClient.fetch });
  Object.defineProperty(client, "baseURL", { ...fixed, value: baseURL });
  Object.defineProperty(client, "httpClient", { ...fixed, value: httpClient });
  givenOptions.set(client, { ...options });
  registerCredential(client, credentialResolver(client, apiKey));
  refuseOpenAIWebSockets(client);
}

/**
 * The options a clone is created with: the client's own, with `options` over
 * them, and never a transport. The parameter type has no `fetch` or
 * `baseURL`; one passed from untyped code is dropped here all the same. A
 * credential given to the clone replaces the inherited one whichever form it
 * takes: `apiKey` clears an inherited `bearerToken`, and `bearerToken`
 * clears an inherited `apiKey`.
 */
function inherit(client: OpenAI, options: Partial<OpenAIClientOptions>): OpenAIClientOptions {
  const merged: Partial<ClientOptions> & { bearerToken?: string } = { ...givenOptions.get(client), ...options };
  delete merged.fetch;
  delete merged.baseURL;
  if ("apiKey" in options && !("bearerToken" in options)) delete merged.bearerToken;
  if ("bearerToken" in options && !("apiKey" in options)) delete merged.apiKey;
  return merged;
}

/**
 * An OpenAI client whose requests go through an {@link AttestedHTTPClient}.
 * Its constructor does no network I/O: the HTTP client was verified, or
 * fetched the gateway's catalog, when it was created, and verifies again by
 * itself. `H` is the type of the HTTP client, so `httpClient` keeps it.
 *
 * The base URL is `options.apiPath` (`/v1/` by default) joined under the
 * HTTP client's EHBP proxy, with or without a trailing slash, under the
 * enclave's HTTPS origin, or under a gateway client's URL. The
 * client sets it after the caller's OpenAI options, so a `baseURL` among
 * them, `OPENAI_BASE_URL` in the environment and `dataResidency` have no
 * effect; set `apiPath` among the options to change the API path:
 * `new OpenAIClient(httpClient, { apiKey, apiPath: "/openai/v1/" })`.
 *
 * Errors: a call through the OpenAI API surface, such as
 * `chat.completions.create(...)`, goes through the OpenAI client's request
 * loop, which catches whatever the attested `fetch` throws, retries the
 * request `maxRetries` times (2 by default; a request whose body is a
 * stream isn't retried) and then throws `APIConnectionError` with the
 * client's error as its `cause`. An enclave that fails to verify again on a
 * request thus surfaces as an `APIConnectionError` caused by an
 * `AttestationError`, after three verification attempts; `maxRetries: 0` on
 * the client or the request shows the first failure. `findTinfoilError` from
 * `tinfoil` returns the SDK error behind an OpenAI error, or undefined.
 *
 * WebSockets: the openai package's WebSocket classes, such as `ResponsesWS`
 * and `OpenAIRealtimeWS`, throw a {@link ConfigurationError} when they are
 * given this client, before they open anything, since the connection that
 * they would open isn't pinned to the attested key. Use
 * `createRealtimeWebSocket` or `createWebSocket` instead, or, on Node, give
 * the class a plain OpenAI client for the enclave together with
 * `pinnedWebSocketOptions(client.httpClient)`.
 */
export class OpenAIClient<H extends AttestedHTTPClient = AttestedHTTPClient> extends OpenAI {
  /**
   * The HTTP client requests go through. It verifies the service behind the
   * route again when the verification expires or its key changes, and is
   * bound to that service. A request's body and the response to it are
   * protected end to end; don't rely on headers, or a request without a body,
   * being private.
   */
  declare readonly httpClient: H;

  /**
   * An OpenAI client over `httpClient`, which must be an
   * {@link EnclaveHTTPClient}, a {@link RouterHTTPClient} or a
   * {@link GatewayHTTPClient} that its factory created; anything else is a
   * {@link ConfigurationError}, and so is an invalid `options.apiPath`.
   */
  constructor(httpClient: H, options?: OpenAIClientOptions) {
    // The API path was a separate argument before the OpenAI options; untyped code that still passes three is refused rather than losing the third.
    if (arguments.length > 2) {
      throw new ConfigurationError("OpenAIClient takes the HTTP client and one options object: pass apiPath among the OpenAI options, as in new OpenAIClient(httpClient, { apiKey, apiPath })");
    }
    const given = options ?? {};
    const baseURL = apiBaseURL(httpClient, given.apiPath);
    const clientOptions = openAIClientOptions(given);
    // The transport and base URL come last, so that the caller's options can't replace them.
    super({ ...clientOptions, fetch: httpClient.fetch, baseURL });
    attest(this, httpClient, baseURL, given, clientOptions.apiKey);
  }

  /**
   * A client with `options` applied over this one's options, on the same
   * attested transport, and on the same API path unless `options` sets
   * `apiPath`. `fetch` and `baseURL` aren't options here: the transport owns
   * them, and one passed from untyped code is ignored. An option that would
   * choose another transport, such as `provider`, is a
   * {@link ConfigurationError}.
   */
  override withOptions(options: Partial<OpenAIClientOptions>): this {
    return new OpenAIClient(this.httpClient, inherit(this, options)) as this;
  }

  /** Closes `httpClient` at the end of an `await using` block; see its `close`. */
  [asyncDispose](): Promise<void> {
    return this.httpClient.close();
  }
}

/** @internal The API path an OpenAI client was created with; undefined for the default. */
export function apiPathOf(client: OpenAI): string | undefined {
  return givenOptions.get(client)?.apiPath;
}

/**
 * @internal The recommended-route factory with its test seams;
 * {@link createClient} is this with the default router options and no seams.
 */
export async function createTinfoilClient(openaiOptions: OpenAIClientOptions, seams: RouterClientSeams, routerOptions: RouterOptions = {}): Promise<OpenAIClient<RouterHTTPClient>> {
  // The OpenAI options are checked first, so a client with the wrong ones fails before any network I/O.
  checkOpenAIOptions(openaiOptions, seams.globals);
  const httpClient = await createRouterHTTPClient(routerOptions, seams);
  try {
    return new OpenAIClient(httpClient, openaiOptions);
  } catch (err) {
    await httpClient.close();
    throw err;
  }
}

/**
 * An OpenAI client for Tinfoil's recommended route: a
 * {@link RouterHTTPClient} that `RouterHTTPClient.create` creates with the
 * default options, verified before it returns, and an {@link OpenAIClient}
 * over it with `options`. The options, `apiPath` included, are checked
 * before any network I/O.
 */
export function createClient(options?: OpenAIClientOptions): Promise<OpenAIClient<RouterHTTPClient>> {
  return createTinfoilClient(options ?? {}, {});
}
