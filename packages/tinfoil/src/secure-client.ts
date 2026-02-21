import { Verifier, ConfigurationError, FetchError, AttestationError, type VerificationDocument } from "./verifier.js";
import type { AttestationBundle } from "./verifier.js";
import { TINFOIL_CONFIG } from "./config.js";
import { createSecureFetch, type SecureTransport } from "./secure-fetch.js";
import { fetchAttestationBundle } from "./atc.js";
import { getEhbp } from "./encrypted-body-fetch.js";
import type { SessionRecoveryToken } from "./encrypted-body-fetch.js";

/** Delay before retrying init on transient failure (ms). */
const INIT_RETRY_DELAY_MS = 1000;

/**
 * Transport mode for secure communication with the enclave.
 *
 * - `'ehbp'` - HPKE encryption via the Encrypted HTTP Body Protocol (default).
 *   End-to-end encrypted, works through proxies.
 * - `'tls'` - TLS certificate pinning. Requires direct connection to the enclave;
 *   requests through a proxy will fail.
 *
 * @see https://docs.tinfoil.sh/resources/ehbp - EHBP Protocol specification
 */
export type TransportMode = 'ehbp' | 'tls';

/**
 * Configuration options for SecureClient.
 */
export interface SecureClientOptions {
  /**
   * Override the base URL for API requests.
   * When set, requests are sent to this URL instead of directly to the enclave.
   * Useful for proxying requests through your own backend.
   * @see https://docs.tinfoil.sh/guides/proxy-server
   */
  baseURL?: string;

  /**
   * Explicit enclave URL. When set, this takes precedence over the domain
   * returned by the attestation bundle.
   * Use this when connecting to a custom enclave endpoint rather than the default router.
   */
  enclaveURL?: string;

  /** GitHub repo for code verification. Defaults to tinfoilsh/confidential-model-router. */
  configRepo?: string;

  /**
   * Transport mode for secure communication.
   * @default 'ehbp'
   */
  transport?: TransportMode;

  /** URL to fetch the attestation bundle from. */
  attestationBundleURL?: string;
}

/**
 * Duck-typed check for EHBP KeyConfigMismatchError.
 * TODO: Replace with direct import once ehbp publishes typed errors.
 */
function isKeyConfigMismatchError(error: unknown): boolean {
  return error instanceof Error && error.name === 'KeyConfigMismatchError';
}

function createPendingVerificationDocument(configRepo: string): VerificationDocument {
  return {
    configRepo,
    enclaveHost: '',
    releaseDigest: '',
    codeMeasurement: { type: '', registers: [] },
    enclaveMeasurement: { measurement: { type: '', registers: [] } },
    tlsPublicKey: '',
    hpkePublicKey: '',
    codeFingerprint: '',
    enclaveFingerprint: '',
    selectedRouterEndpoint: '',
    securityVerified: false,
    steps: {
      fetchDigest: { status: 'pending' },
      verifyCode: { status: 'pending' },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
    },
  };
}

/**
 * Low-level secure client providing a verified fetch function for custom HTTP requests.
 * 
 * SecureClient performs enclave attestation verification and provides a `fetch` function
 * that encrypts all request bodies end-to-end. Use this when you need direct control
 * over HTTP requests or want to use a different OpenAI client.
 * 
 * For most use cases, prefer {@link TinfoilAI} which wraps this with an OpenAI-compatible API.
 * 
 * @example
 * ```typescript
 * import { SecureClient } from "tinfoil";
 * 
 * const client = new SecureClient();
 * await client.ready();
 * 
 * // Use with OpenAI SDK
 * const openai = new OpenAI({
 *   apiKey: "your-key",
 *   baseURL: client.getBaseURL(),
 *   fetch: client.fetch,
 * });
 * ```
 * 
 * @example
 * ```typescript
 * // Direct fetch for custom requests
 * const response = await client.fetch("/v1/chat/completions", {
 *   method: "POST",
 *   headers: { "Content-Type": "application/json" },
 *   body: JSON.stringify({ model: "llama3-3-70b", messages: [...] }),
 * });
 * ```
 * 
 * @see https://docs.tinfoil.sh/sdk/javascript-sdk
 * @see https://docs.tinfoil.sh/guides/proxy-server - Proxy server setup
 */
export class SecureClient {
  // --- Immutable config (from constructor, never changes) ---
  private readonly config: {
    readonly baseURL?: string;
    readonly enclaveURL?: string;
    readonly configRepo: string;
    readonly transport: TransportMode;
    readonly attestationBundleURL?: string;
  };

  // --- Derived state (cleared on reset) ---
  private initPromise: Promise<void> | null = null;
  private verificationDocument: VerificationDocument;
  private _transport: SecureTransport | null = null;
  private resolvedEnclaveURL?: string;
  private resolvedBaseURL?: string;

  constructor(options: SecureClientOptions = {}) {
    if (options.enclaveURL && !options.enclaveURL.startsWith("https://")) {
      throw new ConfigurationError(`enclaveURL must use HTTPS. Got: ${options.enclaveURL}`);
    }
    if (options.configRepo && !options.enclaveURL) {
      throw new ConfigurationError("configRepo requires enclaveURL — without it, ATC always uses the default router repo.");
    } else if (options.enclaveURL && !options.configRepo) {
      console.warn(`[tinfoil] No configRepo specified, verifying against "${TINFOIL_CONFIG.DEFAULT_ROUTER_REPO}".`);
    }

    this.config = {
      baseURL: options.baseURL,
      enclaveURL: options.enclaveURL,
      configRepo: options.configRepo ?? TINFOIL_CONFIG.DEFAULT_ROUTER_REPO,
      transport: options.transport || 'ehbp',
      attestationBundleURL: options.attestationBundleURL,
    };
    this.verificationDocument = createPendingVerificationDocument(this.config.configRepo);
  }

  /**
   * Wait for the client to complete verification and be ready for requests.
   * 
   * This performs enclave attestation, code verification, and establishes
   * the secure transport. Must be called before using `fetch`.
   * 
   * @throws Error if verification fails
   */
  public async ready(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.initSecureClient().catch(async err => {
        // Only try recovery if the error is transient (network I/O, attestation errors)
        if (err instanceof FetchError || err instanceof AttestationError) {
          this.clearDerivedState(); // Start with a new enclave
          await new Promise(r => setTimeout(r, INIT_RETRY_DELAY_MS));
          return this.initSecureClient().catch(retryErr => {
            this.reset();
            throw retryErr;
          });
        }
        // Everything else (ConfigurationError, bugs) — propagate immediately
        this.reset();
        throw err;
      });
    }
    return this.initPromise;
  }

  /**
   * Clear derived state without touching initPromise (preserves deduplication).
   */
  private clearDerivedState(): void {
    this._transport = null;
    this.verificationDocument = createPendingVerificationDocument(this.config.configRepo);
    this.resolvedEnclaveURL = undefined;
    this.resolvedBaseURL = undefined;
  }

  /**
   * Reset the client, clearing all verification state and transport.
   * 
   * After calling reset(), the next call to `ready()` or `fetch()` will
   * perform a fresh attestation and establish a new secure transport.
   * 
   * Use this for retry logic when the enclave may have restarted with new keys,
   * or when you want to force re-verification.
   * 
   * @example
   * ```typescript
   * // Force re-attestation
   * client.reset();
   * await client.ready();
   * 
   * // Or let it re-attest lazily on next request
   * client.reset();
   * await client.fetch("/v1/chat/completions", { ... });
   * ```
   */
  public reset(): void {
    this.initPromise = null;
    this.clearDerivedState();
  }

  private async initSecureClient(): Promise<void> {
    const bundle: AttestationBundle = await fetchAttestationBundle({
      atcBaseUrl: this.config.attestationBundleURL,
      enclaveURL: this.config.enclaveURL,
      configRepo: this.config.configRepo !== TINFOIL_CONFIG.DEFAULT_ROUTER_REPO
        ? this.config.configRepo
        : undefined,
    });

    // Resolve enclaveURL: user-provided config takes precedence, otherwise from bundle
    this.resolvedEnclaveURL = this.config.enclaveURL ?? `https://${bundle.domain}`;

    // Resolve baseURL: user-provided config (proxy) takes precedence, otherwise from enclave
    this.resolvedBaseURL = this.config.baseURL ?? `${this.resolvedEnclaveURL}/v1/`;

    const verifier = new Verifier({
      configRepo: this.config.configRepo,
    });

    try {
      const attestation = await verifier.verifyBundle(bundle);
      this._transport = await this.createTransport(attestation.hpkePublicKey, attestation.tlsPublicKeyFingerprint);
    } finally {
      // Always capture the verifier's doc (success or partial-failure)
      this.verificationDocument = verifier.getVerificationDocument() ?? this.verificationDocument;
    }
  }

  /**
   * Get the verification document containing attestation details.
   * 
   * @returns The verification document with attestation results
   * @see https://docs.tinfoil.sh/verification/attestation-architecture
   */
  public getVerificationDocument(): VerificationDocument {
    return this.verificationDocument;
  }

  /**
   * Get the base URL for API requests.
   * 
   * Returns the base URL requests will be sent to.
   */
  public getBaseURL(): string | undefined {
    return this.resolvedBaseURL;
  }

  /**
   * Get the URL of the enclave endpoint, or undefined before ready().
   */
  public getEnclaveURL(): string | undefined {
    return this.resolvedEnclaveURL;
  }

  private async createTransport(hpkePublicKey?: string, tlsPublicKeyFingerprint?: string): Promise<SecureTransport> {
    if (this.config.transport === 'tls') {
      return await createSecureFetch(this.resolvedBaseURL!, undefined, tlsPublicKeyFingerprint, this.resolvedEnclaveURL);
    }

    return await createSecureFetch(this.resolvedBaseURL!, hpkePublicKey, undefined, this.resolvedEnclaveURL);
  }

  /**
   * Secure fetch function that encrypts request bodies end-to-end.
   *
   * Use this as a drop-in replacement for global `fetch`. Request bodies are
   * encrypted using HPKE (or TLS pinning if configured) so only the verified
   * enclave can decrypt them.
   *
   * On `KeyConfigMismatchError` (server key rotation), automatically re-attests
   * and retries the request once. All other errors propagate to the caller.
   *
   * @example
   * ```typescript
   * const response = await client.fetch("/v1/chat/completions", {
   *   method: "POST",
   *   headers: { "Content-Type": "application/json" },
   *   body: JSON.stringify({ model: "llama3-3-70b", messages: [...] }),
   * });
   * ```
   */
  get fetch(): typeof fetch {
    return async (input: RequestInfo | URL, init?: RequestInit) => {
      await this.ready();

      try {
        return await this._transport!.fetch(input, init);
      } catch (error) {
        // Channel recovery: server rotated keys, request was never processed — safe to retry
        if (isKeyConfigMismatchError(error)) {
          this.reset();
          await this.ready();
          return await this._transport!.fetch(input, init);
        }
        throw error;
      }
    };
  }

  public async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
    if (!this._transport) {
      throw new Error('No session recovery token available — call fetch() first');
    }
    return this._transport.getSessionRecoveryToken();
  }

  static async decryptRecoveryResponse(
    response: Response,
    token: SessionRecoveryToken,
  ): Promise<Response> {
    const { decryptResponseWithToken } = await getEhbp();
    return decryptResponseWithToken(response, token);
  }
}