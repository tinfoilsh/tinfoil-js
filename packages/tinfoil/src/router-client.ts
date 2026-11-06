/**
 * An HTTP client whose requests reach only the attested router it discovered:
 * the first router from Tinfoil's router list that passes verification, and
 * otherwise inference.tinfoil.sh. Discovery runs again each time a client is
 * created and tries routers for at most 30 seconds before falling back.
 */
import type { Verification } from "@tinfoilsh/verifier";
import { attestedFetch, checkNetworkFetch, modeFor, resolveTransportMode, setOpenAIURL, type EnclaveClientSeams } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import { resolveUserCacheSecret } from "./internal/cachesecret.js";
import { asyncDispose } from "./internal/dispose.js";
import { discoverRouter } from "./internal/router.js";
import { normalizeBaseURL, validateBaseURL } from "./internal/transport/base-url.js";
import type { KeyedTransport } from "./internal/transport/transport.js";
import { registerWebSocketAccess } from "./internal/websocket.js";
import type { CallOptions, Fetch, RouterOptions } from "./options.js";

/** @internal Seams for tests: the enclave client's, and the fetch that retrieves the router list. */
export interface RouterClientSeams extends EnclaveClientSeams {
  readonly routersFetch?: Fetch;
  /** Resolves the cache secret when the option is empty. */
  readonly resolveSecret?: (explicit: string | undefined) => Promise<string>;
}

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const TOKEN: unique symbol = Symbol("RouterHTTPClient");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (transport: KeyedTransport, baseURL: string, openAIURL: string, fetchImpl: Fetch) => RouterHTTPClient;

/** @internal The factory with its test seams; {@link RouterHTTPClient.create} is this without them. */
export async function createRouterHTTPClient(options: RouterOptions, seams: RouterClientSeams): Promise<RouterHTTPClient> {
  const mode = resolveTransportMode(options.transportMode, seams.globals);
  checkNetworkFetch(mode, options.fetch);
  let baseURL = options.baseURL ?? "";
  if (baseURL !== "") {
    validateBaseURL(baseURL);
    if (mode === "tls") {
      throw new ConfigurationError('a base URL is a proxy when discovering the router, which requires transportMode "ehbp"');
    }
    baseURL = normalizeBaseURL(baseURL);
  }
  if (options.verifier?.callerAuthorizesConfig) {
    throw new ConfigurationError("caller-authorized config requires an explicit enclave");
  }
  const transport = await discoverRouter({
    verifier: options.verifier,
    verificationCheck: options.verificationCheck,
    mode: modeFor(mode, options.fetch, seams),
    signal: options.signal,
    routersFetch: seams.routersFetch,
    documentFetch: seams.documentFetch,
    clock: seams.clock,
    nonce: seams.nonce,
    sleep: seams.sleep,
  });
  const secret = await (seams.resolveSecret ?? resolveUserCacheSecret)(options.userCacheSecret);
  const host = transport.enclave().host();
  const client = construct(
    transport,
    baseURL !== "" ? baseURL : `https://${host}/`,
    baseURL !== "" ? baseURL : `https://${host}/v1/`,
    attestedFetch(transport, host, baseURL, secret),
  );
  registerWebSocketAccess(client, transport, seams.tls ?? {});
  // Discovery leaves its fallback unverified.
  await client.ensureVerified({ signal: options.signal });
  return client;
}

/**
 * An HTTP client bound to the attested router it discovered; see the module
 * header. The constructor is private: type-checked code cannot call it, and
 * a call from untyped code is refused at runtime. Clients come from
 * {@link RouterHTTPClient.create}, and from the factories built over it:
 * `createClient` and {@link TinfoilClient.create},
 * {@link RouterOpenAIClient.create}, and the AI SDK provider.
 */
export class RouterHTTPClient {
  /** As {@link EnclaveHTTPClient.fetch}. */
  readonly fetch: Fetch;
  /** Where requests go: the `baseURL` option, or the router's own origin. Always ends with `/`, so a relative path resolves against it with `new URL(path, client.baseURL)`. */
  readonly baseURL: string;
  /** The host of the verified router, even when `baseURL` is a proxy. */
  readonly enclave: string;
  /** The repository the router is verified against. */
  readonly repo: string;
  readonly #transport: KeyedTransport;

  private constructor(token: typeof TOKEN, transport: KeyedTransport, baseURL: string, openAIURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("RouterHTTPClient is created with RouterHTTPClient.create");
    this.#transport = transport;
    this.fetch = fetchImpl;
    this.baseURL = baseURL;
    this.enclave = transport.enclave().host();
    this.repo = transport.enclave().repo();
    setOpenAIURL(this, openAIURL);
    // The client's state lives in the transport; the client itself never changes once created.
    Object.freeze(this);
  }

  static {
    construct = (...parts) => new RouterHTTPClient(TOKEN, ...parts);
  }

  /**
   * A client for the discovered router. Options are checked before any
   * network I/O; the router is verified before the client is returned. The
   * user cache secret is resolved, when the option is empty, from the
   * environment and then the persisted secret.
   */
  static create(options?: RouterOptions): Promise<RouterHTTPClient> {
    return createRouterHTTPClient(options ?? {}, {});
  }

  /** The last successful verification, unchecked: it may have expired or been rejected. */
  get current(): Verification | undefined {
    return this.#transport.current();
  }

  /** A verification valid now, verifying first only if the cached one has expired or been rejected. */
  ensureVerified(options?: CallOptions): Promise<Verification> {
    return this.#transport.ensureVerified(options?.signal);
  }

  /** Verifies again even if the cached verification is still valid. */
  reverify(options?: CallOptions): Promise<Verification> {
    return this.#transport.reverify(options?.signal);
  }

  /** Releases what the client holds and refuses further use, as {@link EnclaveHTTPClient.close} does. */
  async close(): Promise<void> {
    this.#transport.close();
  }

  /** Closes the client at the end of an `await using` block; see {@link close}. */
  [asyncDispose](): Promise<void> {
    return this.close();
  }
}
