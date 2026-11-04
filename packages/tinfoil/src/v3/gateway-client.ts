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
import { notImplemented } from "./internal/not-implemented.js";
import type { Catalog, GatewayOptions, ReplicaVerification } from "./options.js";

export class GatewayHTTPClient {
  /** As {@link EnclaveHTTPClient.fetch}. */
  readonly fetch: typeof fetch;

  private constructor() {
    this.fetch = (): Promise<Response> => notImplemented("GatewayHTTPClient.fetch");
  }

  /**
   * Checks the options before any network I/O, then fetches the catalog
   * before returning. A model's replicas are verified on its first request,
   * so `modelPins` may name models the catalog doesn't list.
   */
  static async create(options?: GatewayOptions): Promise<GatewayHTTPClient> {
    void options;
    return notImplemented("GatewayHTTPClient.create");
  }

  /** The gateway's base URL, which requests are sent to. */
  baseURL(): string {
    return notImplemented("GatewayHTTPClient.baseURL");
  }

  /** The catalog's models that the client's policy serves, sorted, without verifying replicas. */
  async models(signal?: AbortSignal): Promise<string[]> {
    void signal;
    return notImplemented("GatewayHTTPClient.models");
  }

  /** A verification valid now of a replica serving `model`, verifying replicas only if needed. */
  async ensureVerified(model: string, signal?: AbortSignal): Promise<Verification> {
    void model;
    void signal;
    return notImplemented("GatewayHTTPClient.ensureVerified");
  }

  /** The last successful verification of each replica used so far, unchecked. */
  current(): ReplicaVerification[] {
    return notImplemented("GatewayHTTPClient.current");
  }
}

/**
 * Reads the catalog of the gateway at `host`, keeping only models with
 * replicas of a bare `tinfoilsh/` repository, without a tag or digest. The
 * catalog is untrusted: replicas are verified when they are used.
 */
export async function fetchCatalog(host: string, signal?: AbortSignal): Promise<Catalog> {
  void host;
  void signal;
  return notImplemented("fetchCatalog");
}
