/**
 * An HTTP client for Tinfoil inference through the gateway. Each request is
 * sealed to a verified replica of the model it names, as with the `"ehbp"`
 * transport: the gateway sees the method, URL and headers, and protocol
 * upgrades are refused.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import type { Verification } from "@tinfoilsh/verifier";
import type { EnclaveClientSeams } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import { resolveUserCacheSecret } from "./internal/cachesecret.js";
import { asyncDispose } from "./internal/dispose.js";
import { fetchCatalogWith } from "./internal/gateway/catalog.js";
import { GatewayPolicy } from "./internal/gateway/policy.js";
import { GatewayTransport } from "./internal/gateway/transport.js";
import { withOriginRestriction } from "./internal/transport/origin.js";
import type { CallOptions, Catalog, Fetch, GatewayOptions, ReplicaVerification } from "./options.js";

/**
 * Tinfoil's gateway, used when no `url` option is given.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export const DEFAULT_GATEWAY_URL = "https://inference-gateway.tinfoil.sh/v1/";

/**
 * Seams for tests: the enclave client's, the catalog fetch, and the secret resolution.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export interface GatewayClientSeams extends Omit<EnclaveClientSeams, "tls"> {
  readonly catalogFetch?: Fetch;
  readonly resolveSecret?: (explicit: string | undefined) => Promise<string>;
}

/** Marks construction by this module's factory; the constructor refuses anything else. */
const TOKEN = Symbol("GatewayHTTPClient");

/**
 * The factory with its test seams; {@link GatewayHTTPClient.create} is this without them.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export async function createGatewayHTTPClient(options: GatewayOptions, seams: GatewayClientSeams): Promise<GatewayHTTPClient> {
  const baseURL = options.url === undefined || options.url === "" ? DEFAULT_GATEWAY_URL : options.url;
  let base: URL;
  try {
    base = new URL(baseURL);
  } catch {
    throw new ConfigurationError(`gateway base URL must be an absolute HTTPS URL: ${JSON.stringify(baseURL)}`);
  }
  if (base.protocol !== "https:" || base.host === "") throw new ConfigurationError(`gateway base URL must be an absolute HTTPS URL: ${JSON.stringify(baseURL)}`);
  // Credentials in the URL would go out in plaintext to the gateway with every request.
  if (base.username !== "" || base.password !== "") throw new ConfigurationError("gateway base URL must not carry a username or password");
  const policy = await GatewayPolicy.create(options.modelPins, options.pinnedModelsOnly ?? false, options.verifier);
  const secret = await (seams.resolveSecret ?? resolveUserCacheSecret)(options.userCacheSecret);
  const transport = new GatewayTransport({
    baseURL,
    relay: base.host,
    catalog: options.catalog,
    policy,
    verificationCheck: options.verificationCheck,
    secret,
    catalogFetch: seams.catalogFetch,
    documentFetch: seams.documentFetch,
    clock: seams.clock,
    nonce: seams.nonce,
    sleep: seams.sleep,
    ehbp: seams.ehbp,
  });
  const client = new GatewayHTTPClient(TOKEN, transport, baseURL, withOriginRestriction(transport.fetch, "", baseURL));
  // An unreachable gateway fails here rather than on the first request.
  await client.models({ signal: options.signal });
  return client;
}

/**
 * The HTTP client for Tinfoil inference through the gateway; see the module
 * header for what it protects.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export class GatewayHTTPClient {
  /** As {@link EnclaveHTTPClient.fetch}. */
  readonly fetch: Fetch;
  /** The gateway's base URL, which requests are sent to. */
  readonly baseURL: string;
  readonly #transport: GatewayTransport;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, transport: GatewayTransport, baseURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("GatewayHTTPClient is created with GatewayHTTPClient.create");
    this.#transport = transport;
    this.fetch = fetchImpl;
    this.baseURL = baseURL;
    // The client's state lives in the transport; the client itself never changes once created.
    Object.freeze(this);
  }

  /**
   * Checks the options before any network I/O, then fetches the catalog
   * before returning. A model's replicas are verified on its first request,
   * so `modelPins` may name models the catalog doesn't list.
   */
  static create(options?: GatewayOptions): Promise<GatewayHTTPClient> {
    return createGatewayHTTPClient(options ?? {}, {});
  }

  /**
   * The catalog's models that the client's policy serves, sorted, without
   * verifying replicas. A failed catalog refresh doesn't fail it; only the
   * first fetch can.
   */
  models(options?: CallOptions): Promise<string[]> {
    return this.#transport.models(options?.signal);
  }

  /** A verification valid now of a replica serving `model`, verifying replicas only if needed. */
  ensureVerified(model: string, options?: CallOptions): Promise<Verification> {
    return this.#transport.ensureVerified(model, options?.signal);
  }

  /** The last successful verification of each replica used so far, unchecked: they may have expired or been rejected. A new array on each read. */
  get current(): ReplicaVerification[] {
    return this.#transport.verifications();
  }

  /**
   * Refuses further use: `fetch`, `models` and `ensureVerified` reject with
   * a {@link ConfigurationError} afterwards, and no replica is verified
   * again; `current` still reports the replicas' last verifications.
   * Requests are sealed and sent through the runtime's fetch, so the client
   * holds no connections of its own to release, and a request in flight
   * completes. Closing again does nothing.
   */
  async close(): Promise<void> {
    this.#transport.close();
  }

  /** Closes the client at the end of an `await using` block; see {@link close}. */
  [asyncDispose](): Promise<void> {
    return this.close();
  }
}

/**
 * Reads the catalog of the gateway at `host`, keeping only models with
 * replicas of a bare `tinfoilsh/` repository, without a tag or digest. The
 * catalog is untrusted: replicas are verified when they are used.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function fetchCatalog(host: string, options?: CallOptions): Promise<Catalog> {
  return fetchCatalogWith(host, (input, init) => fetch(input, init), options?.signal);
}
