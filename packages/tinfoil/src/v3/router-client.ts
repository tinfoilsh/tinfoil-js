/**
 * An HTTP client whose requests reach only the attested router it discovered:
 * the first router from Tinfoil's router list that passes verification, and
 * otherwise inference.tinfoil.sh. Discovery runs again each time a client is
 * created and tries routers for at most 30 seconds before falling back.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { attestedFetch, modeFor, resolveTransportMode, setOpenAIURL, type EnclaveClientSeams } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import { resolveUserCacheSecret } from "./internal/cachesecret.js";
import { discoverRouter } from "./internal/router.js";
import { validateBaseURL } from "./internal/transport/base-url.js";
import type { KeyedTransport } from "./internal/transport/transport.js";
import type { Fetch, RouterOptions } from "./options.js";

/** Seams for tests: the enclave client's, and the fetch that retrieves the router list. */
export interface RouterClientSeams extends EnclaveClientSeams {
  readonly routersFetch?: Fetch;
  /** Resolves the cache secret when the option is empty. */
  readonly resolveSecret?: (explicit: string | undefined) => Promise<string>;
}

/** Marks construction by this module's factory; the constructor refuses anything else. */
const TOKEN = Symbol("RouterHTTPClient");

/** The factory with its test seams; {@link RouterHTTPClient.create} is this without them. */
export async function createRouterHTTPClient(options: RouterOptions, seams: RouterClientSeams): Promise<RouterHTTPClient> {
  const mode = resolveTransportMode(options.transportMode, seams.globals);
  const baseURL = options.baseURL ?? "";
  if (baseURL !== "") {
    validateBaseURL(baseURL);
    if (mode === "tls") {
      throw new ConfigurationError('a base URL is a proxy when discovering the router, which requires transportMode "ehbp"');
    }
  }
  if (options.verifier?.callerAuthorizesConfig()) {
    throw new ConfigurationError("caller-authorized config requires an explicit enclave");
  }
  const transport = await discoverRouter({
    verifier: options.verifier,
    verificationCheck: options.verificationCheck,
    mode: modeFor(mode, seams),
    signal: options.signal,
    routersFetch: seams.routersFetch,
    documentFetch: seams.documentFetch,
    clock: seams.clock,
    nonce: seams.nonce,
    sleep: seams.sleep,
  });
  const secret = await (seams.resolveSecret ?? resolveUserCacheSecret)(options.userCacheSecret);
  const host = transport.enclave().host();
  const client = new RouterHTTPClient(
    TOKEN,
    transport,
    baseURL !== "" ? baseURL : `https://${host}/`,
    baseURL !== "" ? baseURL : `https://${host}/v1/`,
    attestedFetch(transport, host, baseURL, secret),
  );
  // Discovery leaves its fallback unverified.
  await client.ensureVerified(options.signal);
  return client;
}

export class RouterHTTPClient {
  /** As {@link EnclaveHTTPClient.fetch}. */
  readonly fetch: Fetch;
  readonly #transport: KeyedTransport;
  readonly #baseURL: string;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, transport: KeyedTransport, baseURL: string, openAIURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("RouterHTTPClient is created with RouterHTTPClient.create");
    this.#transport = transport;
    this.#baseURL = baseURL;
    this.fetch = fetchImpl;
    setOpenAIURL(this, openAIURL);
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

  /** Where requests go: the `baseURL` option, or the router's own origin. */
  baseURL(): string {
    return this.#baseURL;
  }

  /** The host of the verified router, even when `baseURL` is a proxy. */
  enclave(): string {
    return this.#transport.enclave().host();
  }

  /** The repository the router is verified against. */
  repo(): string {
    return this.#transport.enclave().repo();
  }

  /** The last successful verification, unchecked: it may have expired or been rejected. */
  current(): Verification | undefined {
    return this.#transport.current();
  }

  /** A verification valid now, verifying first only if the cached one has expired or been rejected. */
  ensureVerified(signal?: AbortSignal): Promise<Verification> {
    return this.#transport.ensureVerified(signal);
  }

  /** Verifies again even if the cached verification is still valid. */
  reverify(signal?: AbortSignal): Promise<Verification> {
    return this.#transport.reverify(signal);
  }
}
