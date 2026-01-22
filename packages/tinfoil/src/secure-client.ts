import { Verifier, type AttestationBundle, type VerificationDocument } from "./verifier.js";
import { TINFOIL_CONFIG } from "./config.js";
import { createSecureFetch } from "./secure-fetch.js";
import { fetchAttestationBundle } from "./atc.js";

export type TransportMode = 'auto' | 'ehbp' | 'tls';

interface SecureClientOptions {
  baseURL?: string;
  enclaveURL?: string;
  configRepo?: string;
  transport?: TransportMode;
  attestationBundleURL?: string;
}

export class SecureClient {
  private initPromise: Promise<void> | null = null;
  private verificationDocument: VerificationDocument | null = null;
  private _fetch: typeof fetch | null = null;
  private _didFallbackToTls = false;
  private _tlsPublicKeyFingerprint?: string;

  private baseURL?: string;
  private enclaveURL?: string;
  private readonly configRepo?: string;
  private readonly transport: TransportMode;
  private readonly attestationBundleURL?: string;

  constructor(options: SecureClientOptions = {}) {
    this.baseURL = options.baseURL;
    this.enclaveURL = options.enclaveURL;
    this.configRepo = options.configRepo || TINFOIL_CONFIG.DEFAULT_ROUTER_REPO;
    this.transport = options.transport || 'auto';
    this.attestationBundleURL = options.attestationBundleURL;
  }

  public async ready(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.initSecureClient();
    }
    return this.initPromise;
  }

  private async initSecureClient(): Promise<void> {
    // If no enclave specified, fetch attestation bundle for a router
    let bundle: AttestationBundle | undefined;
    if (!this.enclaveURL) {
      bundle = await fetchAttestationBundle(this.attestationBundleURL);
      this.enclaveURL = `https://${bundle.domain}`;
    }

    // Derive baseURL if not set
    if (!this.baseURL) {
      const enclaveUrl = new URL(this.enclaveURL);
      this.baseURL = `${enclaveUrl.origin}/v1/`;
    }

    const verifier = new Verifier({
      serverURL: this.enclaveURL,
      configRepo: this.configRepo!,
    });

    try {
      if (bundle) {
        await verifier.verifyBundle(bundle);
      } else {
        await verifier.verify();
      }

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
          configRepo: this.configRepo!,
          enclaveHost: new URL(this.enclaveURL!).hostname,
          releaseDigest: '',
          codeMeasurement: { type: '', registers: [] },
          enclaveMeasurement: { measurement: { type: '', registers: [] } },
          tlsPublicKey: '',
          hpkePublicKey: '',
          hardwareMeasurement: undefined,
          codeFingerprint: '',
          enclaveFingerprint: '',
          selectedRouterEndpoint: new URL(this.enclaveURL!).hostname,
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

  public getBaseURL(): string | undefined {
    return this.baseURL;
  }

  private async createTransport(hpkePublicKey?: string, tlsPublicKeyFingerprint?: string): Promise<typeof fetch> {
    if (this.transport === 'tls') {
      return await createSecureFetch(this.baseURL!, this.enclaveURL!, undefined, tlsPublicKeyFingerprint);
    }

    if (this.transport === 'ehbp') {
      return await createSecureFetch(this.baseURL!, this.enclaveURL!, hpkePublicKey, undefined);
    }

    // 'auto' mode: use EHBP, store TLS fingerprint for lazy fallback if needed
    this._tlsPublicKeyFingerprint = tlsPublicKeyFingerprint;
    return await createSecureFetch(this.baseURL!, this.enclaveURL!, hpkePublicKey, undefined);
  }

  private isNotSupportedError(error: unknown): boolean {
    return error instanceof Error &&
      (error.name === 'NotSupportedError' ||
       error.message.includes('NotSupportedError') ||
       error.message.includes('unsupported'));
  }

  get fetch(): typeof fetch {
    return async (input: RequestInfo | URL, init?: RequestInit) => {
      await this.ready();

      try {
        return await this._fetch!(input, init);
      } catch (error) {
        // In 'auto' mode, fall back to TLS on NotSupportedError (e.g., X25519 not available)
        if (this.transport === 'auto' && !this._didFallbackToTls && this._tlsPublicKeyFingerprint && this.isNotSupportedError(error)) {
          this._didFallbackToTls = true;
          this._fetch = await createSecureFetch(this.baseURL!, this.enclaveURL!, undefined, this._tlsPublicKeyFingerprint);
          return await this._fetch(input, init);
        }

        if (this.verificationDocument) {
          const errorMessage = (error as Error).message;

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