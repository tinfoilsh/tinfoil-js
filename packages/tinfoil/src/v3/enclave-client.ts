/**
 * An HTTP client whose requests reach only one attested enclave. The client
 * verifies the enclave before its factory returns, verifies again by itself
 * when the verification expires or is rejected, and refuses requests to any
 * origin other than the one it is bound to.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { isRealBrowser } from "../env.js";
import { ConfigurationError } from "./errors.js";
import { Enclave, type EnclaveConfig } from "./internal/enclave.js";
import { validateBaseURL, validateTLSBaseURL } from "./internal/transport/base-url.js";
import { ehbpMode, type EHBPOptions } from "./internal/transport/ehbp.js";
import { withEnclaveURL } from "./internal/transport/header.js";
import { withOriginRestriction } from "./internal/transport/origin.js";
import { withReplay } from "./internal/transport/replay.js";
import { tlsMode, type TLSOptions } from "./internal/transport/tls.js";
import { isKeyRejection, KeyedTransport, type Mode } from "./internal/transport/transport.js";
import type { EnclaveOptions, Fetch, TransportMode } from "./options.js";

/** Seams for tests: the fetch that retrieves attestation documents, the clock, and the modes' settings. */
export interface EnclaveClientSeams {
  readonly documentFetch?: Fetch;
  readonly clock?: () => Date;
  readonly nonce?: () => Uint8Array;
  readonly sleep?: EnclaveConfig["sleep"];
  readonly tls?: TLSOptions;
  readonly ehbp?: EHBPOptions;
}

const openAIURLs = new WeakMap<object, string>();

/** Where an OpenAI client over `client` sends requests: the base URL option, or the enclave's `/v1/` API. */
export function openAIURLOf(client: object): string {
  const url = openAIURLs.get(client);
  if (url === undefined) throw new ConfigurationError("client was not created by its factory");
  return url;
}

/** `mode`, or the platform's default: pinned connections where the runtime exposes them, sealed bodies in browsers. */
export function resolveTransportMode(mode: TransportMode | undefined): TransportMode {
  if (mode === undefined) return isRealBrowser() ? "ehbp" : "tls";
  if (mode === "tls" || mode === "ehbp") return mode;
  throw new ConfigurationError(`unknown transport mode ${JSON.stringify(mode)}`);
}

export function modeFor(mode: TransportMode, seams: EnclaveClientSeams): Mode {
  return mode === "tls" ? tlsMode(seams.tls) : ehbpMode(seams.ehbp);
}

/**
 * The fetch chain the enclave and router clients send through, from the
 * inside out: the proxy header, one replay after a key rejection, and origin
 * pinning.
 */
export function attestedFetch(transport: KeyedTransport, host: string, baseURL: string): Fetch {
  let chain = withEnclaveURL(transport.fetch, host, baseURL);
  chain = withReplay(chain, isKeyRejection);
  return withOriginRestriction(chain, host, baseURL);
}

/** The option checks that need no network I/O, so a misconfigured client fails before anything is fetched. */
export function checkEnclaveOptions(host: string, options: EnclaveOptions): { mode: TransportMode; baseURL: string } {
  if (host === "") throw new ConfigurationError("enclave host is required");
  const mode = resolveTransportMode(options.transportMode);
  const baseURL = options.baseURL ?? "";
  if (baseURL !== "") validateBaseURL(baseURL);
  if (mode === "tls") validateTLSBaseURL(baseURL, host);
  return { mode, baseURL };
}

/** Marks construction by this module's factory; the constructor refuses anything else. */
const TOKEN = Symbol("EnclaveHTTPClient");

/** The factory with its test seams; {@link EnclaveHTTPClient.create} is this without them. */
export async function createEnclaveHTTPClient(host: string, repo: string, options: EnclaveOptions, seams: EnclaveClientSeams): Promise<EnclaveHTTPClient> {
  const { mode, baseURL } = checkEnclaveOptions(host, options);
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
  const transport = new KeyedTransport(enclave, modeFor(mode, seams), seams.clock);
  const client = new EnclaveHTTPClient(
    TOKEN,
    transport,
    baseURL !== "" ? baseURL : `https://${host}/`,
    baseURL !== "" ? baseURL : `https://${host}/v1/`,
    attestedFetch(transport, host, baseURL),
  );
  await client.ensureVerified(options.signal);
  return client;
}

export class EnclaveHTTPClient {
  /**
   * Sends a request through the attested transport. Bound, so it can be
   * passed as a `fetch` implementation. A request to another origin is a
   * {@link ConfigurationError}.
   */
  readonly fetch: Fetch;
  readonly #transport: KeyedTransport;
  readonly #baseURL: string;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, transport: KeyedTransport, baseURL: string, openAIURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("EnclaveHTTPClient is created with EnclaveHTTPClient.create");
    this.#transport = transport;
    this.#baseURL = baseURL;
    this.fetch = fetchImpl;
    openAIURLs.set(this, openAIURL);
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

  /** Where requests go: the `baseURL` option, or the enclave's own origin. */
  baseURL(): string {
    return this.#baseURL;
  }

  /** The host of the verified enclave, even when `baseURL` is a proxy. */
  enclave(): string {
    return this.#transport.enclave().host();
  }

  /** The repository pin, empty when the verifier authorizes the config instead. */
  repo(): string {
    return this.#transport.enclave().repo();
  }

  /** The last successful verification, unchecked: it may have expired or been rejected. */
  current(): Verification | undefined {
    return this.#transport.current();
  }

  /**
   * A verification valid now, verifying first only if the cached one has
   * expired or been rejected. Success means requests can be sent.
   */
  ensureVerified(signal?: AbortSignal): Promise<Verification> {
    return this.#transport.ensureVerified(signal);
  }

  /** Verifies again even if the cached verification is still valid. */
  reverify(signal?: AbortSignal): Promise<Verification> {
    return this.#transport.reverify(signal);
  }
}
