import { Verifier, type VerificationDocument } from "./verifier.js";
import { TINFOIL_CONFIG } from "./config.js";
import { createSecureFetch } from "./secure-fetch.js";
import { fetchAttestationBundle } from "./atc.js";

/**
 * Transport mode for secure communication with the enclave.
 *
 * - `'ehbp'` - HPKE encryption via the Encrypted HTTP Body Protocol (default).
 *   End-to-end encrypted, works through proxies. Requires X25519 WebCrypto support.
 * - `'tls'` - TLS certificate pinning. Requires direct connection to the enclave;
 *   requests through a proxy will fail. Use this in runtimes without X25519 support (like Bun).
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
  private verificationDocument: VerificationDocument | null = null;
  private _fetch: typeof fetch | null = null;
  private resolvedEnclaveURL?: string;
  private resolvedBaseURL?: string;

  constructor(options: SecureClientOptions = {}) {
    this.config = {
      baseURL: options.baseURL,
      enclaveURL: options.enclaveURL,
      configRepo: options.configRepo || TINFOIL_CONFIG.DEFAULT_ROUTER_REPO,
      transport: options.transport || 'ehbp',
      attestationBundleURL: options.attestationBundleURL,
    };
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
      this.initPromise = this.initSecureClient();
    }
    return this.initPromise;
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
    this._fetch = null;
    this.verificationDocument = null;
    this.resolvedEnclaveURL = undefined;
    this.resolvedBaseURL = undefined;
  }

  private async initSecureClient(): Promise<void> {
    const bundle = await fetchAttestationBundle(this.config.attestationBundleURL);

    // Resolve enclaveURL: user-provided config takes precedence, otherwise from bundle
    this.resolvedEnclaveURL = this.config.enclaveURL ?? `https://${bundle.domain}`;

    // Resolve baseURL: user-provided config (proxy) takes precedence, otherwise from enclave
    this.resolvedBaseURL = this.config.baseURL ?? `${this.resolvedEnclaveURL}/v1/`;

    const verifier = new Verifier({
      configRepo: this.config.configRepo,
    });

    try {
      await verifier.verifyBundle(bundle);

      const doc = verifier.getVerificationDocument();
      if (!doc) {
        throw new Error("Internal error: Verification document unavailable after successful attestation verification");
      }
      this.verificationDocument = doc;

      // Extract keys from the verification document
      const { hpkePublicKey, tlsPublicKeyFingerprint } = this.verificationDocument.enclaveMeasurement;

      try {
        this._fetch = await this.createTransport(hpkePublicKey, tlsPublicKeyFingerprint);
      } catch (transportError) {
        this.verificationDocument.steps.createTransport = {
          status: 'failed',
          error: (transportError as Error).message
        };
        this.verificationDocument.securityVerified = false;
        throw transportError;
      }
    } catch (error) {
      const doc = verifier.getVerificationDocument();
      if (doc) {
        this.verificationDocument = doc;
      } else {
        this.verificationDocument = {
          configRepo: this.config.configRepo,
          enclaveHost: bundle.domain,
          releaseDigest: '',
          codeMeasurement: { type: '', registers: [] },
          enclaveMeasurement: { measurement: { type: '', registers: [] } },
          tlsPublicKey: '',
          hpkePublicKey: '',
          hardwareMeasurement: undefined,
          codeFingerprint: '',
          enclaveFingerprint: '',
          selectedRouterEndpoint: bundle.domain,
          securityVerified: false,
          steps: {
            fetchDigest: { status: 'pending' },
            verifyCode: { status: 'pending' },
            verifyEnclave: { status: 'pending' },
            compareMeasurements: { status: 'pending' },
            createTransport: undefined,
            verifyHPKEKey: undefined,
            otherError: { status: 'failed', error: (error as Error).message },
          }
        };
      }
      throw error;
    }
  }

  /**
   * Get the verification document containing attestation details.
   * 
   * @returns The verification document with attestation results
   * @throws Error if verification has not completed
   * @see https://docs.tinfoil.sh/verification/attestation-architecture
   */
  public async getVerificationDocument(): Promise<VerificationDocument> {
    if (!this.initPromise) {
      await this.ready();
    }

    await this.initPromise!.catch(() => {});

    if (!this.verificationDocument) {
      throw new Error("Internal error: Verification document unavailable. Call ready() before accessing verification details");
    }
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

  private async createTransport(hpkePublicKey?: string, tlsPublicKeyFingerprint?: string): Promise<typeof fetch> {
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
   * On failure, automatically re-verifies attestation and retries once in case
   * the enclave restarted with new keys.
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
        return await this._fetch!(input, init);
      } catch (error) {
        if (!(error instanceof Error)) {
          throw error;
        }

        // Retry once - enclave may have restarted with new keys
        this.reset();
        try {
          await this.ready();
          return await this._fetch!(input, init);
        } catch {
          // Retry failed, throw original error
        }

        // Update verification document with error info
        if (this.verificationDocument) {
          const errorMessage = error.message;

          if (errorMessage.includes('HPKE public key mismatch')) {
            this.verificationDocument.steps.verifyHPKEKey = {
              status: 'failed',
              error: errorMessage
            };
            this.verificationDocument.securityVerified = false;
          } else if (errorMessage.includes('Transport initialization failed') || errorMessage.includes('Request initialization failed')) {
            this.verificationDocument.steps.createTransport = {
              status: 'failed',
              error: errorMessage
            };
            this.verificationDocument.securityVerified = false;
          } else if (errorMessage.includes('Failed to get HPKE key')) {
            this.verificationDocument.steps.verifyHPKEKey = {
              status: 'failed',
              error: errorMessage
            };
            this.verificationDocument.securityVerified = false;
          } else {
            this.verificationDocument.steps.otherError = {
              status: 'failed',
              error: errorMessage
            };
            this.verificationDocument.securityVerified = false;
          }
        }

        throw error;
      }
    };
  }
}