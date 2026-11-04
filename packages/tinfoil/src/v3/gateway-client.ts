/**
 * An HTTP client for Tinfoil inference through the gateway. Each request is
 * sealed to a verified replica of the model it names, as with the `"ehbp"`
 * transport: the gateway sees the method, URL and headers, and protocol
 * upgrades are refused.
 *
 * Experimental: the gateway route is new, and this API may change or be
 * removed in a later release.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import type { EnclaveClientSeams } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import { resolveUserCacheSecret } from "./internal/cachesecret.js";
import { fetchCatalogWith } from "./internal/gateway/catalog.js";
import { GatewayPolicy } from "./internal/gateway/policy.js";
import { GatewayTransport } from "./internal/gateway/transport.js";
import { withOriginRestriction } from "./internal/transport/origin.js";
import type { Catalog, Fetch, GatewayOptions, ReplicaVerification } from "./options.js";

export const DEFAULT_GATEWAY_URL = "https://inference-gateway.tinfoil.sh/v1/";

/** Seams for tests: the enclave client's, the catalog fetch, and the secret resolution. */
export interface GatewayClientSeams extends Omit<EnclaveClientSeams, "tls"> {
  readonly catalogFetch?: Fetch;
  readonly resolveSecret?: (explicit: string | undefined) => Promise<string>;
}

/** Marks construction by this module's factory; the constructor refuses anything else. */
const TOKEN = Symbol("GatewayHTTPClient");

/** The factory with its test seams; {@link GatewayHTTPClient.create} is this without them. */
export async function createGatewayHTTPClient(options: GatewayOptions, seams: GatewayClientSeams): Promise<GatewayHTTPClient> {
  const baseURL = options.url === undefined || options.url === "" ? DEFAULT_GATEWAY_URL : options.url;
  let base: URL;
  try {
    base = new URL(baseURL);
  } catch {
    throw new ConfigurationError(`gateway base URL must be an absolute HTTPS URL: ${JSON.stringify(baseURL)}`);
  }
  if (base.protocol !== "https:" || base.host === "") throw new ConfigurationError(`gateway base URL must be an absolute HTTPS URL: ${JSON.stringify(baseURL)}`);
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
  await client.models(options.signal);
  return client;
}

export class GatewayHTTPClient {
  /** As {@link EnclaveHTTPClient.fetch}. */
  readonly fetch: Fetch;
  readonly #transport: GatewayTransport;
  readonly #baseURL: string;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, transport: GatewayTransport, baseURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("GatewayHTTPClient is created with GatewayHTTPClient.create");
    this.#transport = transport;
    this.#baseURL = baseURL;
    this.fetch = fetchImpl;
  }

  /**
   * Checks the options before any network I/O, then fetches the catalog
   * before returning. A model's replicas are verified on its first request,
   * so `modelPins` may name models the catalog doesn't list.
   */
  static create(options?: GatewayOptions): Promise<GatewayHTTPClient> {
    return createGatewayHTTPClient(options ?? {}, {});
  }

  /** The gateway's base URL, which requests are sent to. */
  baseURL(): string {
    return this.#baseURL;
  }

  /**
   * The catalog's models that the client's policy serves, sorted, without
   * verifying replicas. A failed catalog refresh doesn't fail it; only the
   * first fetch can.
   */
  models(signal?: AbortSignal): Promise<string[]> {
    return this.#transport.models(signal);
  }

  /** A verification valid now of a replica serving `model`, verifying replicas only if needed. */
  ensureVerified(model: string, signal?: AbortSignal): Promise<Verification> {
    return this.#transport.ensureVerified(model, signal);
  }

  /** The last successful verification of each replica used so far, unchecked: they may have expired or been rejected. */
  current(): ReplicaVerification[] {
    return this.#transport.verifications();
  }
}

/**
 * Reads the catalog of the gateway at `host`, keeping only models with
 * replicas of a bare `tinfoilsh/` repository, without a tag or digest. The
 * catalog is untrusted: replicas are verified when they are used.
 */
export function fetchCatalog(host: string, signal?: AbortSignal): Promise<Catalog> {
  return fetchCatalogWith(host, (input, init) => fetch(input, init), signal);
}
