import { fetchRouter } from "./atc.js";

interface UnverifiedClientOptions {
  /** Base URL for API requests. If not provided, derived from keyOrigin or fetched from router. */
  baseURL?: string;
  /** Origin URL for fetching the HPKE public key. If not provided, derived from baseURL. */
  keyOrigin?: string;
}

export class UnverifiedClient {
  private initPromise: Promise<void> | null = null;
  private _fetch: typeof fetch | null = null;

  private baseURL?: string;
  private keyOrigin?: string;

  constructor(options: UnverifiedClientOptions = {}) {
    this.baseURL = options.baseURL;
    this.keyOrigin = options.keyOrigin;
  }

  public async ready(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.initUnverifiedClient();
    }
    return this.initPromise;
  }

  private async initUnverifiedClient(): Promise<void> {
    // Only fetch router if neither baseURL nor keyOrigin is provided
    if (!this.baseURL && !this.keyOrigin) {
      const routerAddress = await fetchRouter();
      this.keyOrigin = `https://${routerAddress}`;
      this.baseURL = `https://${routerAddress}/v1/`;
    }

    // Ensure both baseURL and keyOrigin are initialized
    if (!this.baseURL) {
      if (this.keyOrigin) {
        const keyOriginUrl = new URL(this.keyOrigin);
        this.baseURL = `${keyOriginUrl.origin}/v1/`;
      } else {
        throw new Error("Unable to determine baseURL: neither baseURL nor keyOrigin provided");
      }
    }

    if (!this.keyOrigin) {
      if (this.baseURL) {
        const baseUrl = new URL(this.baseURL);
        this.keyOrigin = baseUrl.origin;
      } else {
        throw new Error("Unable to determine keyOrigin: neither baseURL nor keyOrigin provided");
      }
    }

    // Dynamically import to avoid loading ehbp/hpke modules at module load time
    const { createUnverifiedEncryptedBodyFetch } = await import("./encrypted-body-fetch.js");
    this._fetch = createUnverifiedEncryptedBodyFetch(this.baseURL, this.keyOrigin);
  }

  public async getVerificationDocument(): Promise<void> {
    if (!this.initPromise) {
      await this.ready();
    }
    
    await this.initPromise;

    throw new Error("Verification document unavailable: this version of the client is unverified");
  }

  get fetch(): typeof fetch {
    return async (input: RequestInfo | URL, init?: RequestInit) => {
      await this.ready();
      return this._fetch!(input, init);
    };
  }
}