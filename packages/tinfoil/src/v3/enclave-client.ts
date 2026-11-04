/**
 * An HTTP client whose requests reach only one attested enclave. The client
 * verifies the enclave before its factory returns, verifies again by itself
 * when the verification expires or is rejected, and refuses requests to any
 * origin other than the one it is bound to.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { notImplemented } from "./internal/not-implemented.js";
import type { EnclaveOptions, Fetch } from "./options.js";

export class EnclaveHTTPClient {
  /**
   * Sends a request through the attested transport. Bound, so it can be
   * passed as a `fetch` implementation. A request to another origin is a
   * {@link ConfigurationError}.
   */
  readonly fetch: Fetch;

  private constructor() {
    this.fetch = (): Promise<Response> => notImplemented("EnclaveHTTPClient.fetch");
  }

  /**
   * A client for the enclave at `host`, verified against `repo`
   * (`owner/name[@tag][@sha256:digest]`). An empty `repo` accepts configs
   * authorized by the verifier option. Options are checked before any network
   * I/O; the enclave is verified before the client is returned.
   */
  static async create(host: string, repo: string, options?: EnclaveOptions): Promise<EnclaveHTTPClient> {
    void host;
    void repo;
    void options;
    return notImplemented("EnclaveHTTPClient.create");
  }

  /** Where requests go: the `baseURL` option, or the enclave's own origin. */
  baseURL(): string {
    return notImplemented("EnclaveHTTPClient.baseURL");
  }

  /** The host of the verified enclave, even when `baseURL` is a proxy. */
  enclave(): string {
    return notImplemented("EnclaveHTTPClient.enclave");
  }

  /** The repository pin, empty when the verifier authorizes the config instead. */
  repo(): string {
    return notImplemented("EnclaveHTTPClient.repo");
  }

  /** The last successful verification, unchecked: it may have expired or been rejected. */
  current(): Verification | undefined {
    return notImplemented("EnclaveHTTPClient.current");
  }

  /**
   * A verification valid now, verifying first only if the cached one has
   * expired or been rejected. Success means requests can be sent.
   */
  async ensureVerified(signal?: AbortSignal): Promise<Verification> {
    void signal;
    return notImplemented("EnclaveHTTPClient.ensureVerified");
  }

  /** Verifies again even if the cached verification is still valid. */
  async reverify(signal?: AbortSignal): Promise<Verification> {
    void signal;
    return notImplemented("EnclaveHTTPClient.reverify");
  }
}
