import type { VerifierOptions } from "@tinfoilsh/verifier";
import { SecureClient, configuredVerifier, validateReference, waitFor, type SecureClientOptions, type VerificationSnapshot, type TransportMode } from "./secure-client.js";
import { ConfigurationError, AttestationError, NetworkError, isBindingRejection, recoveryFailure } from "./errors.js";
import { fetchRouters, httpURL, copyAcquisitionOptions, type AcquisitionOptions } from "./acquisition.js";
import { TINFOIL_CONFIG } from "./config.js";
import { prepareRequest } from "./request.js";
import { resolveUserCacheSecret, injectUserCacheSecretIntoRequestInit } from "./user-cache-secret.js";
import type { SessionRecoveryToken } from "ehbp";

export interface ClientOptions {
  enclaveURL?: string;
  configRepo?: string;
  baseURL?: string;
  transport?: TransportMode;
  verification?: VerifierOptions;
  acquisition?: AcquisitionOptions;
  discoveryURL?: string;
  userCacheSecret?: string;
}
/** SDK selection and replay; SecureClient remains the only enclave lifecycle owner. */
export class Client {
  readonly #options: Readonly<ClientOptions>;
  readonly #handles = new Map<string, SecureClient>();
  readonly #providerOrigins = new Set<string>();
  #selected?: SecureClient;
  #selection?: Promise<SecureClient>;
  #secret?: Promise<string>;
  #lastRequestClient?: SecureClient;
  constructor(options: ClientOptions = {}) {
    if (options.baseURL !== undefined) httpURL(options.baseURL, "baseURL");
    if (options.transport !== undefined && options.transport !== "ehbp" && options.transport !== "tls") throw new ConfigurationError("Unknown transport mode");
    if (options.transport === "tls" && options.baseURL && new URL(options.baseURL).protocol !== "https:") throw new ConfigurationError("TLS requires HTTPS");
    if (options.discoveryURL !== undefined) httpURL(options.discoveryURL, "discoveryURL", true);
    if (options.configRepo && !options.enclaveURL) throw new ConfigurationError("A custom trusted reference requires an explicit enclaveURL");
    if (!options.enclaveURL && (options.verification?.embeddedReferences?.config || options.verification?.configAuthorizer)) throw new ConfigurationError("Caller-authorized configuration requires an explicit enclaveURL");
    const customConfig = !!(options.verification?.embeddedReferences?.config || options.verification?.configAuthorizer);
    const reference = options.configRepo ?? (customConfig ? "" : TINFOIL_CONFIG.DEFAULT_ROUTER_REPO);
    validateReference(reference, customConfig);
    // Verifier validates and copies nested trust data. Each handle gets an independently
    // copied configuration below; retain a detached input for handles discovered later.
    configuredVerifier(options.verification);
    this.#options = Object.freeze({ ...options, verification: copyVerificationOptions(options.verification), configRepo: reference, acquisition: copyAcquisitionOptions(options.acquisition) });
    if (options.enclaveURL) this.#selected = this.#handle(httpURL(options.enclaveURL, "enclaveURL", true).origin);
  }
  #handle(endpoint: string): SecureClient {
    let handle = this.#handles.get(endpoint);
    if (!handle) {
      handle = new SecureClient({ ...this.#options, enclaveURL: endpoint } as SecureClientOptions);
      this.#handles.set(endpoint, handle);
    }
    return handle;
  }
  async #select(signal?: AbortSignal): Promise<SecureClient> {
    if (this.#selected) { await this.#selected.ready({ signal }); return this.#selected; }
    if (!this.#selection) {
      const work = (async () => {
        let endpoints: string[];
        try { endpoints = await fetchRouters(this.#options.discoveryURL, this.#options.acquisition); }
        catch (error) { if (!(error instanceof NetworkError)) throw error; endpoints = []; }
        endpoints = [...new Set([...endpoints, "https://inference.tinfoil.sh"])];
        let failure: unknown;
        for (const endpoint of endpoints) {
          try { const handle = this.#handle(endpoint); await handle.ready(); this.#selected = handle; return handle; }
          catch (error) { if (!(error instanceof NetworkError || error instanceof AttestationError)) throw error; failure = error; }
        }
        throw failure;
      })();
      this.#selection = work;
      void work.then(() => { if (this.#selection === work) this.#selection = undefined; }, () => { if (this.#selection === work) this.#selection = undefined; });
    }
    return waitFor(this.#selection, signal);
  }
  async ready(options: { signal?: AbortSignal } = {}): Promise<void> { await this.#select(options.signal); }
  inspect(): VerificationSnapshot | undefined { return this.#selected?.inspect(); }
  getBaseURL(): string {
    const base = this.#options.baseURL ?? this.#selected?.getBaseURL() ?? "https://inference.tinfoil.sh/v1/";
    this.#providerOrigins.add(new URL(base).origin);
    return base;
  }
  async selectedClient(): Promise<SecureClient> { return this.#select(); }
  readonly fetch: typeof fetch = async (input, init) => {
    const base = this.getBaseURL();
    const request = prepareRequest(input, init, base, [...this.#providerOrigins]);
    const handle = await this.#select(request.init.signal ?? undefined);
    // A provider can keep a prior base URL; reconcile its path against the selected
    // destination, while accepting only origins this SDK previously supplied.
    const destination = new URL(handle.getBaseURL());
    request.url.protocol = destination.protocol; request.url.host = destination.host;
    this.#secret ??= resolveUserCacheSecret(this.#options.userCacheSecret);
    request.init = (await injectUserCacheSecretIntoRequestInit(request.init, request.url.pathname, await this.#secret))!;
    this.#lastRequestClient = handle;
    try { return await handle.fetch(request.url, request.init); }
    catch (error) {
      if (!isBindingRejection(error) || !request.replayable) throw error;
      request.init.signal?.throwIfAborted();
      try {
        await handle.ready({ signal: request.init.signal ?? undefined });
        return await handle.fetch(request.url, request.init);
      } catch (terminal) { throw recoveryFailure(terminal, error); }
    }
  };
  async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
    if (!this.#lastRequestClient) throw new ConfigurationError("No request has supplied a session recovery token");
    return this.#lastRequestClient.getSessionRecoveryToken();
  }
}
/** Copy policy bytes without serializing callbacks or losing typed arrays. */
export function copyVerificationOptions(options?: VerifierOptions): VerifierOptions | undefined {
  if (!options) return undefined;
  const copy = (value: unknown): unknown => {
    if (value instanceof Uint8Array) return value.slice();
    if (Array.isArray(value)) return value.map(copy);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, copy(entry)]));
    return value;
  };
  return copy(options) as VerifierOptions;
}
