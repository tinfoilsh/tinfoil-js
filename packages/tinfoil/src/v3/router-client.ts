/**
 * An HTTP client whose requests reach only the attested router it discovered:
 * the first router from Tinfoil's router list that passes verification, and
 * otherwise inference.tinfoil.sh. Discovery runs again each time a client is
 * created and tries routers for at most 30 seconds before falling back.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { notImplemented } from "./internal/not-implemented.js";
import type { RouterOptions } from "./options.js";

export class RouterHTTPClient {
  /** As {@link EnclaveHTTPClient.fetch}. */
  readonly fetch: typeof fetch;

  private constructor() {
    this.fetch = (): Promise<Response> => notImplemented("RouterHTTPClient.fetch");
  }

  /** Options are checked before any network I/O; the router is verified before the client is returned. */
  static async create(options?: RouterOptions): Promise<RouterHTTPClient> {
    void options;
    return notImplemented("RouterHTTPClient.create");
  }

  /** Where requests go: the `baseURL` option, or the router's own origin. */
  baseURL(): string {
    return notImplemented("RouterHTTPClient.baseURL");
  }

  /** The host of the verified router, even when `baseURL` is a proxy. */
  enclave(): string {
    return notImplemented("RouterHTTPClient.enclave");
  }

  /** The repository the router is verified against. */
  repo(): string {
    return notImplemented("RouterHTTPClient.repo");
  }

  /** The last successful verification, unchecked. */
  current(): Verification | undefined {
    return notImplemented("RouterHTTPClient.current");
  }

  /** A verification valid now, verifying only if needed. */
  async ensureVerified(signal?: AbortSignal): Promise<Verification> {
    void signal;
    return notImplemented("RouterHTTPClient.ensureVerified");
  }

  /** Verifies again even if the cached verification is still valid. */
  async reverify(signal?: AbortSignal): Promise<Verification> {
    void signal;
    return notImplemented("RouterHTTPClient.reverify");
  }
}
