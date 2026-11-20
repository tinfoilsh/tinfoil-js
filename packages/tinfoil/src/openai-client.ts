/**
 * The OpenAI-compatible client over the attested HTTP clients. One class,
 * {@link OpenAIClient}, takes any of the SDK's three HTTP clients, sends
 * through its attested `fetch`, and sets the OpenAI client's base URL
 * itself: the API path joined under the HTTP client's EHBP proxy or the
 * enclave's origin, or the gateway's URL as given. It applies the caller's
 * OpenAI options first, then sets `fetch` and `baseURL` so that the options
 * can't replace them, and keeps both fixed afterwards, with `httpClient`
 * beside them: the properties can't be assigned, and `withOptions` doesn't
 * take `fetch` or `baseURL` (a clone ignores one passed from untyped code)
 * and keeps the attested transport. A base URL that the caller sets through
 * the OpenAI options, through `OPENAI_BASE_URL` in the environment, or
 * through `dataResidency` has no effect; `apiPath` chooses the API path. The
 * OpenAI options that would choose another transport (`provider`,
 * `workloadIdentity`, `credential` and `x509Transport`) are refused, before
 * any network I/O and by `withOptions`. Per-request `fetchOptions` are
 * passed through to the attested `fetch` and can't bypass it.
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
 * pinned only when the HTTP client has no EHBP proxy, so that they connect
 * to the enclave itself over `wss://`. Behind a proxy the pinned handshake
 * fails, and over an `http://` one there is no TLS to pin.
 * `OpenAIRealtimeWebSocket` can't be pinned, and the gateway client has no
 * pinned WebSocket, so don't give it to those classes at all.
 *
 * The HTTP client owns the lifecycle: `httpClient.close()` releases it, and
 * an `await using` of the OpenAI client does the same, for its clones too,
 * since they share the transport.
 */
import OpenAI, { type ClientOptions } from "openai";
import type { EnclaveHTTPClient } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import type { GatewayHTTPClient } from "./gateway-client.js";
import { apiBaseURL } from "./internal/api-path.js";
import { checkAPIKeyRuntime, registerCredential, type CredentialResolver } from "./internal/credential.js";
import { asyncDispose } from "./internal/dispose.js";
import type { RuntimeGlobals } from "./internal/platform.js";
import type { RouterOptions } from "./options.js";
import { createRouterHTTPClient, type RouterClientSeams, type RouterHTTPClient } from "./router-client.js";

/**
 * The HTTP clients that an {@link OpenAIClient} can send through: an
 * {@link EnclaveHTTPClient}, a {@link RouterHTTPClient} or a
 * {@link GatewayHTTPClient} that its factory created. Anything else, such as
 * `null` or an object of the caller's own, is a {@link ConfigurationError}.
 */
export type AttestedHTTPClient = EnclaveHTTPClient | RouterHTTPClient | GatewayHTTPClient;

/** Configures an {@link OpenAIClient}: the part of where requests go that the caller may choose. */
export interface OpenAIOptions {
  /**
   * The path of the API, joined under the HTTP client's EHBP proxy or, when
   * there is none, under the enclave's origin; undefined or "" selects
   * `/v1/`. It must be an absolute path (starting with `/` but not `//`),
   * without a query, a fragment, an encoded slash, or a "." or ".." segment,
   * percent-encoded or not; anything else is a {@link ConfigurationError}. A
   * gateway client's URL already carries the API path, so an `apiPath` with
   * one is a {@link ConfigurationError}.
   */
  readonly apiPath?: string;
}

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
 * The OpenAI client's own options that an {@link OpenAIClient} takes:
 * everything but the transport that it is bound to, the base URL that it
 * sets itself (`baseURL` and `dataResidency`, which have no effect when
 * untyped code passes one), and the options that would choose another
 * transport (`provider`, `workloadIdentity`, `credential` and
 * `x509Transport`), which are a {@link ConfigurationError}. An `apiKey` is
 * accepted only where the runtime is a server (Node or Bun); anywhere else,
 * `dangerouslyAllowBrowser` included, it is a {@link ConfigurationError}
 * naming `bearerToken` as the credential to give.
 */
export type OpenAIClientOptions = Omit<ClientOptions, "fetch" | "baseURL" | "dataResidency" | "provider" | "workloadIdentity" | "credential" | "x509Transport"> & {
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
function checkOpenAIOptions(options: OpenAIClientOptions, globals: RuntimeGlobals | undefined): void {
  refuseTransportOptions(options);
  checkAPIKeyRuntime(options.apiKey, globals);
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
  // The base URL options are dropped whatever their value, so they have no effect.
  const rest: Omit<ClientOptions, "fetch" | "baseURL"> = { ...given };
  for (const key of [...FORBIDDEN_TRANSPORT_OPTIONS, ...IGNORED_BASE_URL_OPTIONS]) delete (rest as Record<string, unknown>)[key];
  checkAPIKeyRuntime(rest.apiKey);
  if (bearerToken === undefined || bearerToken === "") return rest;
  return { ...rest, apiKey: bearerToken, dangerouslyAllowBrowser: true };
}

/** The OpenAI options that each client was created with, which its clones inherit. */
const givenOptions = new WeakMap<OpenAI, OpenAIClientOptions>();

/** The options that each client was created with, which its clones keep. */
const givenAPIOptions = new WeakMap<OpenAI, OpenAIOptions>();

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
function attest(client: OpenAI, httpClient: AttestedHTTPClient, baseURL: string, options: OpenAIClientOptions, apiKey: ClientOptions["apiKey"]): void {
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
 * HTTP client's EHBP proxy, with or without a trailing slash, or under the
 * enclave's HTTPS origin; for a gateway client it is the gateway's URL. The
 * client sets it after the caller's OpenAI options, so a `baseURL` among
 * them, `OPENAI_BASE_URL` in the environment and `dataResidency` have no
 * effect; set `apiPath` to change the API path.
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
  constructor(httpClient: H, options?: OpenAIOptions, openaiOptions?: OpenAIClientOptions) {
    const apiOptions: OpenAIOptions = { ...options };
    const baseURL = apiBaseURL(httpClient, apiOptions.apiPath);
    const given = openaiOptions ?? {};
    const clientOptions = openAIClientOptions(given);
    // The transport and base URL come last, so that the caller's options can't replace them.
    super({ ...clientOptions, fetch: httpClient.fetch, baseURL });
    attest(this, httpClient, baseURL, given, clientOptions.apiKey);
    givenAPIOptions.set(this, apiOptions);
  }

  /**
   * A client with `options` applied over this one's OpenAI options, on the
   * same attested transport and API path. `fetch` and `baseURL` aren't
   * options here: the transport owns them, and one passed from untyped code
   * is ignored. An option that would choose another transport, such as
   * `provider`, is a {@link ConfigurationError}.
   */
  override withOptions(options: Partial<OpenAIClientOptions>): this {
    return new OpenAIClient(this.httpClient, givenAPIOptions.get(this), inherit(this, options)) as this;
  }

  /** Closes `httpClient` at the end of an `await using` block; see its `close`. */
  [asyncDispose](): Promise<void> {
    return this.httpClient.close();
  }
}

/** @internal The API path an OpenAI client was created with; "" for the default. */
export function apiPathOf(client: OpenAI): string {
  return givenAPIOptions.get(client)?.apiPath ?? "";
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
    return new OpenAIClient(httpClient, undefined, openaiOptions);
  } catch (err) {
    await httpClient.close();
    throw err;
  }
}

/**
 * An OpenAI client for Tinfoil's recommended route: a
 * {@link RouterHTTPClient} that `RouterHTTPClient.create` creates with the
 * default options, verified before it returns, and an {@link OpenAIClient}
 * over it with `options`.
 */
export function createClient(options?: OpenAIClientOptions): Promise<OpenAIClient<RouterHTTPClient>> {
  return createTinfoilClient(options ?? {}, {});
}
