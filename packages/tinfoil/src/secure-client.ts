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
   * Useful for proxying requests through your own backend.
   * @see https://docs.tinfoil.sh/guides/proxy-server
   */
  baseURL?: string;

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
  private initPromise: Promise<void> | null = null;
  private verificationDocument: VerificationDocument | null = null;
  private _fetch: typeof fetch | null = null;

  private baseURL?: string;
  private enclaveURL?: string;
  private readonly configRepo: string;
  private readonly transport: TransportMode;
  private readonly attestationBundleURL?: string;

  constructor(options: SecureClientOptions = {}) {
    this.baseURL = options.baseURL;
    this.configRepo = options.configRepo || TINFOIL_CONFIG.DEFAULT_ROUTER_REPO;
    this.transport = options.transport || 'ehbp';
    this.attestationBundleURL = options.attestationBundleURL;
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

  private async initSecureClient(): Promise<void> {
    const bundle = await fetchAttestationBundle(this.attestationBundleURL);

    this.enclaveURL = `https://${bundle.domain}`;

    // Derive baseURL from bundle domain if not set
    if (!this.baseURL) {
      this.baseURL = `${this.enclaveURL}/v1/`;
    }

    const verifier = new Verifier({
      configRepo: this.configRepo,
    });

    try {
      await verifier.verifyBundle(bundle);

      const doc = verifier.getVerificationDocument();
      if (!doc) {
        throw new Error("Verification document not available after successful verification");
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
          configRepo: this.configRepo,
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
      throw new Error("Verification document unavailable: client not verified yet");
    }
    return this.verificationDocument;
  }

  /**
   * Get the base URL for API requests.
   * 
   * @returns The base URL (e.g., "https://enclave.example.com/v1/")
   */
  public getBaseURL(): string | undefined {
    return this.baseURL;
  }

  private async createTransport(hpkePublicKey?: string, tlsPublicKeyFingerprint?: string): Promise<typeof fetch> {
    if (this.transport === 'tls') {
      return await createSecureFetch(this.baseURL!, undefined, tlsPublicKeyFingerprint, this.enclaveURL);
    }

    return await createSecureFetch(this.baseURL!, hpkePublicKey, undefined, this.enclaveURL);
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
        this.initPromise = null;
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