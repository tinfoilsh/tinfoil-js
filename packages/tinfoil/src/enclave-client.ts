/**
 * An HTTP client whose requests reach only one attested enclave. The client
 * verifies the enclave before its factory returns, verifies again by itself
 * when the verification expires or is rejected, and refuses requests to any
 * origin other than the one it is bound to.
 */
import { Verifier, type ConfigTrust, type Policy, type Verification } from "@tinfoilsh/verifier";
import { ConfigurationError } from "./errors.js";
import { withCacheSecret } from "./internal/cachesecret.js";
import { registerRoute } from "./internal/api-path.js";
import { asyncDispose } from "./internal/dispose.js";
import { Enclave, fromVerify, type EnclaveConfig } from "./internal/enclave.js";
import { normalizeBaseURL, refuseEnclaveOriginProxy, validateBaseURL } from "./internal/transport/base-url.js";
import { ehbpMode, type EHBPOptions } from "./internal/transport/ehbp.js";
import { withEnclaveURL } from "./internal/transport/header.js";
import { withOriginRestriction } from "./internal/transport/origin.js";
import { checkTransportMode, defaultTransportMode, type RuntimeGlobals } from "./internal/platform.js";
import { withReplay } from "./internal/transport/replay.js";
import { tlsMode, type TLSOptions } from "./internal/transport/tls.js";
import { isKeyRejection, KeyedTransport, type Mode, type TransportMode } from "./internal/transport/transport.js";
import { registerWebSocketAccess } from "./internal/websocket.js";
import type { CallOptions, EnclaveOptions, Fetch, Transport } from "./options.js";
import { cloneTrust, verifierInputs, type Trust } from "./trust.js";

/**
 * @internal Seams for tests: the fetch that retrieves attestation documents,
 * the clock, the modes' settings, the globals the runtime is identified by,
 * and a verifier that replaces the one built from the trust and the policy.
 */
export interface EnclaveClientSeams {
  readonly verifier?: Verifier;
  readonly documentFetch?: Fetch;
  readonly globals?: RuntimeGlobals;
  readonly clock?: () => Date;
  readonly nonce?: () => Uint8Array;
  readonly sleep?: EnclaveConfig["sleep"];
  readonly tls?: TLSOptions;
  readonly ehbp?: EHBPOptions;
}

/** @internal A {@link Transport} as a client uses it: the mode, the proxy ("" for none, otherwise ending with `/`) and the EHBP network fetch. */
export interface ResolvedTransport {
  readonly mode: TransportMode;
  readonly proxyURL: string;
  readonly fetch?: Fetch;
}

/**
 * @internal `transport` after checking the values that its variant carries,
 * or the platform's default for undefined: pinned connections where the
 * runtime exposes them, sealed bodies in browsers. A transport that the
 * platform can't provide, or an unknown `kind`, is a
 * {@link ConfigurationError}.
 */
export function resolveTransport(transport: Transport | undefined, globals?: RuntimeGlobals): ResolvedTransport {
  if (transport === undefined) return { mode: defaultTransportMode(globals), proxyURL: "" };
  if (typeof transport !== "object" || transport === null) throw new ConfigurationError("transport must be an object with a kind");
  switch (transport.kind) {
    case "tls":
      checkTransportMode("tls", globals);
      return { mode: "tls", proxyURL: "" };
    case "ehbp": {
      const proxyURL = transport.proxyURL ?? "";
      if (typeof proxyURL !== "string") throw new ConfigurationError("invalid proxy URL: it must be a string");
      if (proxyURL !== "") validateBaseURL(proxyURL, "proxy URL");
      if (transport.fetch !== undefined && typeof transport.fetch !== "function") throw new ConfigurationError("the EHBP fetch must be a function");
      return { mode: "ehbp", proxyURL: proxyURL === "" ? "" : normalizeBaseURL(proxyURL), ...(transport.fetch === undefined ? {} : { fetch: transport.fetch }) };
    }
    default: {
      const kind = (transport as { kind?: unknown }).kind;
      throw new ConfigurationError(`transport must have kind "tls" or "ehbp", not ${kind === undefined ? "a value without one" : JSON.stringify(kind)}`);
    }
  }
}

/**
 * @internal The EHBP mode's settings: the caller's EHBP `fetch` carries the
 * sealed requests when given; otherwise the seam's fetch does, standing in
 * for the runtime's, so a test of the option runs the same path as a caller.
 */
export function ehbpOptionsFor(fetchImpl: Fetch | undefined, seams: Pick<EnclaveClientSeams, "ehbp">): EHBPOptions {
  return { ...seams.ehbp, fetch: fetchImpl ?? seams.ehbp?.fetch };
}

/** @internal The mode that implements `transport`, with the seams' settings. */
export function modeFor(transport: ResolvedTransport, seams: EnclaveClientSeams): Mode {
  return transport.mode === "tls" ? tlsMode(seams.tls) : ehbpMode(ehbpOptionsFor(transport.fetch, seams));
}

/**
 * @internal The fetch chain the enclave and router clients send through,
 * from the inside out: the proxy header, one replay after a key rejection,
 * the cache secret, and origin pinning. The cache secret sits above the
 * transport, so the field it adds is sealed with the rest of the body or
 * sent over the pinned connection.
 */
export function attestedFetch(transport: KeyedTransport, host: string, proxyURL: string, cacheSecret: string = ""): Fetch {
  let chain = withEnclaveURL(transport.fetch, host, proxyURL);
  chain = withReplay(chain, isKeyRejection);
  chain = withCacheSecret(chain, cacheSecret);
  return withOriginRestriction(chain, host, proxyURL);
}

/** @internal The option checks that need no network I/O, so a misconfigured client fails before anything is fetched. */
export function checkEnclaveOptions(host: string, options: EnclaveOptions, globals?: RuntimeGlobals): ResolvedTransport {
  if (typeof host !== "string" || host === "") throw new ConfigurationError("enclave host is required");
  const transport = resolveTransport(options.transport, globals);
  refuseEnclaveOriginProxy(transport.proxyURL, host);
  return transport;
}

/**
 * @internal The verifier for `config` and `policy`, built before any network
 * I/O; the verifier's usage error is a {@link ConfigurationError}. The
 * seams' verifier replaces it.
 */
export async function buildVerifier(config: ConfigTrust | undefined, policy: Policy | undefined, seams: Pick<EnclaveClientSeams, "verifier">): Promise<Verifier> {
  if (seams.verifier !== undefined) return seams.verifier;
  try {
    return await Verifier.create(config, policy);
  } catch (err) {
    throw fromVerify(err);
  }
}

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const TOKEN: unique symbol = Symbol("EnclaveHTTPClient");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (transport: KeyedTransport, trust: Trust, baseURL: string, fetchImpl: Fetch) => EnclaveHTTPClient;

/** @internal The factory with its test seams; {@link EnclaveHTTPClient.create} is this without them. */
export async function createEnclaveHTTPClient(host: string, trust: Trust, options: EnclaveOptions, seams: EnclaveClientSeams): Promise<EnclaveHTTPClient> {
  const { config, pin } = verifierInputs(trust);
  const resolved = checkEnclaveOptions(host, options, seams.globals);
  const verifier = await buildVerifier(config, options.policy, seams);
  // Copied once the verifier has checked its values, so that the copy is of a valid trust.
  const trustCopy = cloneTrust(trust);
  const enclave = await Enclave.create({
    host,
    pin,
    verifier,
    verificationCheck: options.verificationCheck,
    fetch: seams.documentFetch,
    clock: seams.clock,
    nonce: seams.nonce,
    sleep: seams.sleep,
  });
  const transport = new KeyedTransport(enclave, modeFor(resolved, seams), seams.clock);
  const proxyURL = resolved.proxyURL;
  const client = construct(
    transport,
    trustCopy,
    proxyURL !== "" ? proxyURL : `https://${host}/`,
    attestedFetch(transport, host, proxyURL, options.userCacheSecret ?? ""),
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
 * {@link EnclaveHTTPClient.create}, and from the AI SDK provider's `enclave`
 * option. An `OpenAIClient` from `tinfoil/openai` can be built over one.
 */
export class EnclaveHTTPClient {
  /**
   * Sends a request through the attested transport. Bound, so it can be
   * passed as a `fetch` implementation. A request to another origin is a
   * {@link ConfigurationError}.
   */
  readonly fetch: Fetch;
  /** Where requests go: the EHBP proxy, or the enclave's own origin. Always ends with `/`, so a relative path resolves against it with `new URL(path, client.baseURL)`. */
  readonly baseURL: string;
  /** The host of the verified enclave, even when `baseURL` is a proxy. */
  readonly enclave: string;
  readonly #transport: KeyedTransport;
  readonly #trust: Trust;

  private constructor(token: typeof TOKEN, transport: KeyedTransport, trust: Trust, baseURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("EnclaveHTTPClient is created with EnclaveHTTPClient.create");
    this.#transport = transport;
    this.#trust = trust;
    this.fetch = fetchImpl;
    this.baseURL = baseURL;
    this.enclave = transport.enclave().host();
    registerRoute(this, "enclave");
    // The client's state lives in the transport; the client itself never changes once created.
    Object.freeze(this);
  }

  static {
    construct = (...parts) => new EnclaveHTTPClient(TOKEN, ...parts);
  }

  /**
   * A client for the enclave at `host`, verified under `trust`, which names
   * who vouches for the enclave's config, and the `policy` option. The trust
   * and the options are checked before any network I/O, and the enclave is
   * verified before the client is returned.
   */
  static create(host: string, trust: Trust, options?: EnclaveOptions): Promise<EnclaveHTTPClient> {
    return createEnclaveHTTPClient(host, trust, options ?? {}, {});
  }

  /** A copy of the trust that the enclave is verified under; changing the copy has no effect on the client. */
  get trust(): Trust {
    return cloneTrust(this.#trust);
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
   * TLS transport's pooled connections are closed, which also ends any
   * request still in flight on them with a {@link NetworkError}; the EHBP
   * transport sends through the runtime's fetch, or its own `fetch`, and
   * holds no connections of its own, so a request in flight completes. No verification runs again. Afterwards `fetch`, `ensureVerified`,
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
