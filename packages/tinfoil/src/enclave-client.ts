/**
 * An HTTP client whose requests reach only one attested enclave. The client
 * verifies the enclave before its factory returns, verifies again by itself
 * when the verification expires or is rejected, and refuses requests to any
 * origin other than the one it is bound to.
 */
import type { Verification } from "@tinfoilsh/verifier";
import { ConfigurationError } from "./errors.js";
import { withCacheSecret } from "./internal/cachesecret.js";
import { asyncDispose } from "./internal/dispose.js";
import { Enclave, type EnclaveConfig } from "./internal/enclave.js";
import { normalizeBaseURL, validateBaseURL, validateTLSBaseURL } from "./internal/transport/base-url.js";
import { ehbpMode, type EHBPOptions } from "./internal/transport/ehbp.js";
import { withEnclaveURL } from "./internal/transport/header.js";
import { withOriginRestriction } from "./internal/transport/origin.js";
import { checkTransportMode, defaultTransportMode, type RuntimeGlobals } from "./internal/platform.js";
import { withReplay } from "./internal/transport/replay.js";
import { tlsMode, type TLSOptions } from "./internal/transport/tls.js";
import { isKeyRejection, KeyedTransport, type Mode } from "./internal/transport/transport.js";
import { registerWebSocketAccess } from "./internal/websocket.js";
import type { CallOptions, EnclaveOptions, Fetch, TransportMode } from "./options.js";

/** @internal Seams for tests: the fetch that retrieves attestation documents, the clock, the modes' settings, and the globals the runtime is identified by. */
export interface EnclaveClientSeams {
  readonly documentFetch?: Fetch;
  readonly globals?: RuntimeGlobals;
  readonly clock?: () => Date;
  readonly nonce?: () => Uint8Array;
  readonly sleep?: EnclaveConfig["sleep"];
  readonly tls?: TLSOptions;
  readonly ehbp?: EHBPOptions;
}

const openAIURLs = new WeakMap<object, string>();

/** @internal Where an OpenAI client over `client` sends requests: the base URL option, or the enclave's `/v1/` API. */
export function openAIURLOf(client: object): string {
  const url = openAIURLs.get(client);
  if (url === undefined) throw new ConfigurationError("client was not created by its factory");
  return url;
}

/** @internal Records where an OpenAI client over `client` sends requests. */
export function setOpenAIURL(client: object, url: string): void {
  openAIURLs.set(client, url);
}

/**
 * @internal `mode`, or the platform's default: pinned connections where the
 * runtime exposes them, sealed bodies in browsers. A mode the platform can't
 * provide is a {@link ConfigurationError}.
 */
export function resolveTransportMode(mode: TransportMode | undefined, globals?: RuntimeGlobals): TransportMode {
  if (mode === undefined) return defaultTransportMode(globals);
  if (mode !== "tls" && mode !== "ehbp") throw new ConfigurationError(`unknown transport mode ${JSON.stringify(mode)}`);
  checkTransportMode(mode, globals);
  return mode;
}

/**
 * @internal The EHBP mode's settings: the caller's `fetch` option carries the
 * sealed requests when given; otherwise the seam's fetch does, standing in
 * for the runtime's, so a test of the option runs the same path as a caller.
 */
export function ehbpOptionsFor(fetchImpl: Fetch | undefined, seams: Pick<EnclaveClientSeams, "ehbp">): EHBPOptions {
  return { ...seams.ehbp, fetch: fetchImpl ?? seams.ehbp?.fetch };
}

/** @internal The transport mode's settings: the caller's `fetch` option for the EHBP mode, and the seams. */
export function modeFor(mode: TransportMode, fetchImpl: Fetch | undefined, seams: EnclaveClientSeams): Mode {
  return mode === "tls" ? tlsMode(seams.tls) : ehbpMode(ehbpOptionsFor(fetchImpl, seams));
}

/** @internal Rejects the `fetch` option under the `"tls"` mode, which pins its own connections and sends nothing through a caller's fetch. */
export function checkNetworkFetch(mode: TransportMode, fetchImpl: Fetch | undefined): void {
  if (mode === "tls" && fetchImpl !== undefined) {
    throw new ConfigurationError('the fetch option carries sealed requests, which requires transportMode "ehbp"; the "tls" transport mode pins its own connections');
  }
}

/**
 * @internal The fetch chain the enclave and router clients send through,
 * from the inside out: the proxy header, one replay after a key rejection,
 * the cache secret, and origin pinning. The cache secret sits above the
 * transport, so the field it adds is sealed with the rest of the body or
 * sent over the pinned connection.
 */
export function attestedFetch(transport: KeyedTransport, host: string, baseURL: string, cacheSecret: string = ""): Fetch {
  let chain = withEnclaveURL(transport.fetch, host, baseURL);
  chain = withReplay(chain, isKeyRejection);
  chain = withCacheSecret(chain, cacheSecret);
  return withOriginRestriction(chain, host, baseURL);
}

/** @internal The option checks that need no network I/O, so a misconfigured client fails before anything is fetched. The base URL comes back ending with `/`, or empty. */
export function checkEnclaveOptions(host: string, options: EnclaveOptions, globals?: RuntimeGlobals): { mode: TransportMode; baseURL: string } {
  if (host === "") throw new ConfigurationError("enclave host is required");
  const mode = resolveTransportMode(options.transportMode, globals);
  checkNetworkFetch(mode, options.fetch);
  const baseURL = options.baseURL ?? "";
  if (baseURL !== "") validateBaseURL(baseURL);
  if (mode === "tls") validateTLSBaseURL(baseURL, host);
  return { mode, baseURL: baseURL === "" ? "" : normalizeBaseURL(baseURL) };
}

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const TOKEN: unique symbol = Symbol("EnclaveHTTPClient");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (transport: KeyedTransport, baseURL: string, openAIURL: string, fetchImpl: Fetch) => EnclaveHTTPClient;

/** @internal The factory with its test seams; {@link EnclaveHTTPClient.create} is this without them. */
export async function createEnclaveHTTPClient(host: string, repo: string, options: EnclaveOptions, seams: EnclaveClientSeams): Promise<EnclaveHTTPClient> {
  const { mode, baseURL } = checkEnclaveOptions(host, options, seams.globals);
  const enclave = await Enclave.create({
    host,
    repo,
    verifier: options.verifier,
    verificationCheck: options.verificationCheck,
    fetch: seams.documentFetch,
    clock: seams.clock,
    nonce: seams.nonce,
    sleep: seams.sleep,
  });
  const transport = new KeyedTransport(enclave, modeFor(mode, options.fetch, seams), seams.clock);
  const client = construct(
    transport,
    baseURL !== "" ? baseURL : `https://${host}/`,
    baseURL !== "" ? baseURL : `https://${host}/v1/`,
    attestedFetch(transport, host, baseURL, options.userCacheSecret ?? ""),
  );
  registerWebSocketAccess(client, transport, seams.tls ?? {});
  // A verification that the signal cuts short goes on inside the transport,
  // so the transport is closed when the client isn't returned: what that
  // verification binds when it finishes is then released instead of kept
  // by a client no one holds.
  try {
    await client.ensureVerified({ signal: options.signal });
  } catch (err) {
    await client.close();
    throw err;
  }
  return client;
}

/**
 * An HTTP client bound to one attested enclave; see the module header. The
 * constructor is private: type-checked code cannot call it, and a call from
 * untyped code is refused at runtime. Clients come from
 * {@link EnclaveHTTPClient.create}, and from the factories built over it:
 * {@link EnclaveOpenAIClient.create} and the AI SDK provider's `enclave`
 * option.
 */
export class EnclaveHTTPClient {
  /**
   * Sends a request through the attested transport. Bound, so it can be
   * passed as a `fetch` implementation. A request to another origin is a
   * {@link ConfigurationError}.
   */
  readonly fetch: Fetch;
  /** Where requests go: the `baseURL` option, or the enclave's own origin. Always ends with `/`, so a relative path resolves against it with `new URL(path, client.baseURL)`. */
  readonly baseURL: string;
  /** The host of the verified enclave, even when `baseURL` is a proxy. */
  readonly enclave: string;
  /** The repository pin, empty when the verifier authorizes the config instead. */
  readonly repo: string;
  readonly #transport: KeyedTransport;

  private constructor(token: typeof TOKEN, transport: KeyedTransport, baseURL: string, openAIURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("EnclaveHTTPClient is created with EnclaveHTTPClient.create");
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
    construct = (...parts) => new EnclaveHTTPClient(TOKEN, ...parts);
  }

  /**
   * A client for the enclave at `host`, verified against `repo`
   * (`owner/name[@tag][@sha256:digest]`). An empty `repo` accepts configs
   * authorized by the verifier option. Options are checked before any network
   * I/O; the enclave is verified before the client is returned.
   */
  static create(host: string, repo: string, options?: EnclaveOptions): Promise<EnclaveHTTPClient> {
    return createEnclaveHTTPClient(host, repo, options ?? {}, {});
  }

  /** The last successful verification, unchecked: it may have expired or been rejected. */
  get current(): Verification | undefined {
    return this.#transport.current();
  }

  /**
   * A verification valid now, verifying first only if the cached one has
   * expired or been rejected. Success means requests can be sent.
   */
  ensureVerified(options?: CallOptions): Promise<Verification> {
    return this.#transport.ensureVerified(options?.signal);
  }

  /** Verifies again even if the cached verification is still valid. */
  reverify(options?: CallOptions): Promise<Verification> {
    return this.#transport.reverify(options?.signal);
  }

  /**
   * Releases what the client holds and refuses further use. On Node, the
   * `"tls"` transport's pooled connections are closed, which also ends any
   * request still in flight on them with a {@link NetworkError}; the
   * `"ehbp"` transport sends through the runtime's fetch, or the `fetch`
   * option, and holds no connections of its own, so a request in flight
   * completes. No verification runs again. Afterwards `fetch`, `ensureVerified`,
   * `reverify` and the WebSocket functions reject with a
   * {@link ConfigurationError}; `current` still reports the last
   * verification. Closing again does nothing.
   */
  async close(): Promise<void> {
    this.#transport.close();
  }

  /** Closes the client at the end of an `await using` block; see {@link close}. */
  [asyncDispose](): Promise<void> {
    return this.close();
  }
}
