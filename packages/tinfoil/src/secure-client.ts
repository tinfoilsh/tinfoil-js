import { KeyConfigMismatchError } from "ehbp";
import { Verifier, parseReference, UsageError, VerificationError, randomNonce, type Verification, type VerifierOptions } from "@tinfoilsh/verifier";
import { ConfigurationError, AttestationError, NetworkError, bindingError, isBindingRejection } from "./errors.js";
import { copyAcquisitionOptions, fetchAttestationDocument, httpURL, type AcquisitionOptions } from "./acquisition.js";
import { createSecureFetch } from "./secure-fetch.js";
import type { SecureTransport, SessionRecoveryToken } from "./encrypted-body-fetch.js";
import type { SecureWebSocketOptions } from "./pinned-ws.js";
import type * as WS from "ws";
import { isRealBrowser } from "./env.js";

export type { SecureWebSocketOptions } from "./pinned-ws.js";
export type TransportMode = "ehbp" | "tls";
export interface SecureClientOptions {
  enclaveURL: string;
  configRepo?: string;
  baseURL?: string;
  transport?: TransportMode;
  verification?: VerifierOptions;
  acquisition?: AcquisitionOptions;
  /** Fetch untrusted documents through an explicit HTTPS forwarding relay. */
  attestationRelayURL?: string;
}
export interface VerificationSnapshot {
  readonly endpoint: string;
  readonly verification: Verification;
}
interface EnclaveState {
  readonly verification: Verification;
  readonly transport: SecureTransport;
  readonly expiresAt: number;
  readonly tlsFingerprint?: string;
  rejected: boolean;
}

export function validateReference(reference: string, allowEmpty = false): void {
  if (allowEmpty && reference === "") return;
  try { parseReference(reference); } catch (cause) {
    if (cause instanceof UsageError || (cause instanceof Error && cause.name === "UsageError")) throw new ConfigurationError("Invalid trusted repository or registry reference", { cause });
    throw cause;
  }
}
export function configuredVerifier(options?: VerifierOptions): Verifier {
  try { return new Verifier(options); } catch (cause) {
    if (cause instanceof UsageError || (cause instanceof Error && cause.name === "UsageError")) throw new ConfigurationError("Invalid verification configuration", { cause });
    throw cause;
  }
}
/** Cancel an individual wait without cancelling shared setup needed by other callers. */
export function waitFor<T>(work: Promise<T>, signal?: AbortSignal | null): Promise<T> {
  if (!signal) return work;
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener("abort", abort); reject(signal.reason); };
    signal.addEventListener("abort", abort, { once: true });
    work.then(value => { signal.removeEventListener("abort", abort); resolve(value); }, error => { signal.removeEventListener("abort", abort); reject(error); });
  });
}

/** One fixed enclave, one policy, and one atomic verification/transport association. */
export class SecureClient {
  readonly #endpoint: string;
  readonly #baseURL: string;
  readonly #reference: string;
  readonly #mode: TransportMode;
  readonly #verifier: Verifier;
  readonly #acquisition: Readonly<AcquisitionOptions>;
  readonly #relay?: string;
  #state?: EnclaveState;
  #refresh?: Promise<EnclaveState>;
  #lastRequestState?: EnclaveState;

  constructor(options: SecureClientOptions) {
    if (!options) throw new ConfigurationError("SecureClient requires a fixed enclaveURL");
    const endpoint = httpURL(options.enclaveURL, "enclaveURL", true);
    if (endpoint.pathname !== "/" || endpoint.search) throw new ConfigurationError("enclaveURL must identify an origin");
    this.#endpoint = endpoint.origin;
    this.#baseURL = httpURL(options.baseURL ?? `${endpoint.origin}/v1/`, "baseURL").toString();
    this.#mode = options.transport ?? "ehbp";
    if (this.#mode !== "ehbp" && this.#mode !== "tls") throw new ConfigurationError("Unknown transport mode");
    if (this.#mode === "tls" && (new URL(this.#baseURL).origin !== endpoint.origin || isRealBrowser())) throw new ConfigurationError("TLS requires the direct HTTPS enclave origin and a runtime that exposes peer certificates");
    this.#reference = options.configRepo ?? "";
    validateReference(this.#reference, !!(options.verification?.embeddedReferences?.config || options.verification?.configAuthorizer));
    if (options.verification?.configAuthorizer && this.#reference) throw new ConfigurationError("Config authorizer requires an empty repository reference");
    this.#verifier = configuredVerifier(options.verification);
    this.#acquisition = copyAcquisitionOptions(options.acquisition);
    this.#relay = options.attestationRelayURL && httpURL(options.attestationRelayURL, "attestationRelayURL", true).origin;
  }

  #usable(state: EnclaveState | undefined): state is EnclaveState {
    return !!state && !state.rejected && Number.isFinite(state.expiresAt) && state.expiresAt > Date.now();
  }
  async #attempt(): Promise<EnclaveState> {
    const nonce = randomNonce();
    const document = await fetchAttestationDocument(this.#endpoint, nonce, { ...this.#acquisition, relayURL: this.#relay });
    let verification: Verification;
    try { verification = await this.#verifier.verify(document, nonce, this.#reference); } catch (cause) {
      if (cause instanceof UsageError || (cause instanceof Error && cause.name === "UsageError")) throw new ConfigurationError("Invalid verification request", { cause });
      if (cause instanceof VerificationError || (cause instanceof Error && cause.name === "VerificationError")) throw new AttestationError("Enclave attestation was rejected", { cause });
      throw cause;
    }
    const expiresAt = verification.freshnessExpiresAt?.getTime() ?? NaN;
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new AttestationError("Attestation has no usable authenticated freshness deadline");
    const tlsFingerprint = verification.tlsPublicKeyFingerprint();
    const hpke = verification.hpkePublicKey();
    if (this.#mode === "tls" ? !tlsFingerprint : !hpke) throw new AttestationError(`Attestation does not contain a usable ${this.#mode} binding`);
    const transport = await createSecureFetch(this.#baseURL, this.#mode === "ehbp" ? hpke : undefined, this.#mode === "tls" ? tlsFingerprint : undefined, this.#endpoint);
    const candidate = { verification, transport, expiresAt, tlsFingerprint, rejected: false };
    if (!this.#usable(candidate)) throw new AttestationError("Attestation expired during channel construction");
    return candidate;
  }
  #startRefresh(): Promise<EnclaveState> {
    if (this.#refresh) return this.#refresh;
    const work = (async () => {
      for (let attempt = 0; ; attempt++) {
        try {
          const candidate = await this.#attempt();
          if (!this.#usable(candidate)) throw new AttestationError("Attestation expired before publication");
          this.#state = candidate;
          return candidate;
        } catch (error) {
          if (attempt > 0 || !(error instanceof NetworkError || error instanceof AttestationError)) throw error;
        }
      }
    })();
    this.#refresh = work;
    void work.then(() => { if (this.#refresh === work) this.#refresh = undefined; }, () => { if (this.#refresh === work) this.#refresh = undefined; });
    return work;
  }
  async #admit(signal?: AbortSignal | null): Promise<EnclaveState> {
    signal?.throwIfAborted();
    const state = this.#usable(this.#state) ? this.#state : await waitFor(this.#startRefresh(), signal);
    signal?.throwIfAborted();
    if (!this.#usable(state)) throw new AttestationError("Attestation expired or its key was rejected before request admission");
    return state;
  }
  async ready(options: { signal?: AbortSignal } = {}): Promise<void> { await this.#admit(options.signal); }
  /** Explicit re-verification stays at this endpoint and preserves a valid old state on failure. */
  async refresh(options: { signal?: AbortSignal } = {}): Promise<void> {
    options.signal?.throwIfAborted();
    const state = await waitFor(this.#startRefresh(), options.signal);
    if (!this.#usable(state)) throw new AttestationError("Attestation expired before readiness");
  }
  inspect(): VerificationSnapshot | undefined {
    const state = this.#state;
    return state ? Object.freeze({ endpoint: this.#endpoint, verification: state.verification }) : undefined;
  }
  getBaseURL(): string { return this.#baseURL; }
  getEnclaveURL(): string { return this.#endpoint; }
  getEnclaveBaseURL(): string { return `${this.#endpoint}/v1/`; }

  readonly fetch: typeof fetch = async (input, init) => {
    // Credential-bearing origin guard precedes setup or body access.
    const target = new URL(input instanceof Request ? input.url : String(input), this.#baseURL);
    if (target.origin !== new URL(this.#baseURL).origin) throw new ConfigurationError("Request destination differs from the configured HTTP origin");
    const signal = init?.signal !== undefined ? init.signal : (input instanceof Request ? input.signal : undefined);
    const state = await this.#admit(signal);
    this.#lastRequestState = state;
    try { return await state.transport.fetch(input, init); } catch (cause) {
      if (cause instanceof KeyConfigMismatchError || isBindingRejection(cause)) {
        state.rejected = true;
        throw cause instanceof KeyConfigMismatchError ? bindingError("The enclave rejected the attested channel key", cause) : cause;
      }
      throw cause;
    }
  };
  async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
    if (!this.#lastRequestState) throw new ConfigurationError("No request has supplied a session recovery token");
    return this.#lastRequestState.transport.getSessionRecoveryToken();
  }
  async #webSocketState(): Promise<EnclaveState> {
    if (isRealBrowser()) throw new ConfigurationError("Verified WebSockets require peer-certificate access");
    const state = await this.#admit();
    if (!state.tlsFingerprint) throw new AttestationError("Attestation has no TLS key for WebSockets");
    return state;
  }
  async getPinnedWebSocketOptions(): Promise<WS.ClientOptions> {
    const state = await this.#webSocketState();
    const { pinnedWsClientOptions } = await import("./pinned-ws.js");
    if (!this.#usable(state)) throw new AttestationError("Attestation expired before WebSocket admission");
    return pinnedWsClientOptions(state.tlsFingerprint!);
  }
  async createWebSocket(path: string, options?: SecureWebSocketOptions): Promise<WS.WebSocket> {
    const target = new URL(path, this.#endpoint);
    if (target.protocol === "https:") target.protocol = "wss:";
    if (target.protocol !== "wss:" || target.host !== new URL(this.#endpoint).host || target.username || target.password) throw new ConfigurationError("WebSocket must target the direct verified enclave with WSS");
    const state = await this.#webSocketState();
    const { createPinnedWebSocket } = await import("./pinned-ws.js");
    if (!this.#usable(state)) throw new AttestationError("Attestation expired before WebSocket admission");
    const socket = await createPinnedWebSocket(target.toString(), state.tlsFingerprint!, options);
    socket.once("error", error => { if (isBindingRejection(error)) state.rejected = true; });
    return socket;
  }
}
