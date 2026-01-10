import { fetchRouter } from "./router.js";

interface UnverifiedClientOptions {
  baseURL?: string;
  enclaveURL?: string;
}

export class UnverifiedClient {
  private initPromise: Promise<void> | null = null;
  private _fetch: typeof fetch | null = null;

  private baseURL?: string;
  private enclaveURL?: string;

  constructor(options: UnverifiedClientOptions = {}) {
    this.baseURL = options.baseURL;
    this.enclaveURL = options.enclaveURL;
  }

  public async ready(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.initUnverifiedClient();
    }
    return this.initPromise;
  }

  private async initUnverifiedClient(): Promise<void> {
    // Only fetch router if neither baseURL nor enclaveURL is provided
    if (!this.baseURL && !this.enclaveURL) {
      const routerAddress = await fetchRouter();
      this.enclaveURL = `https://${routerAddress}`;
      this.baseURL = `https://${routerAddress}/v1/`;
    }

    // Ensure both baseURL and enclaveURL are initialized
    if (!this.baseURL) {
      if (this.enclaveURL) {
        // If enclaveURL is provided but baseURL is not, derive baseURL from enclaveURL
        const enclaveUrl = new URL(this.enclaveURL);
        this.baseURL = `${enclaveUrl.origin}/v1/`;
      } else {
        throw new Error("Unable to determine baseURL: neither baseURL nor enclaveURL provided");
      }
    }

    if (!this.enclaveURL) {
      if (this.baseURL) {
        // If baseURL is provided but enclaveURL is not, derive enclaveURL from baseURL
        const baseUrl = new URL(this.baseURL);
        this.enclaveURL = baseUrl.origin;
      } else {
        throw new Error("Unable to determine enclaveURL: neither baseURL nor enclaveURL provided");
      }
    }

    // Dynamically import to avoid loading ehbp/hpke modules at module load time
    const { createEncryptedBodyFetch } = await import("./encrypted-body-fetch.js");
    this._fetch = createEncryptedBodyFetch(this.baseURL, undefined, this.enclaveURL);
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