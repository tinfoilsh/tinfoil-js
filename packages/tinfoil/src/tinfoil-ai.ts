import OpenAI from "openai";
import type {
  Audio,
  Beta,
  Chat,
  Embeddings,
  Files,
  FineTuning,
  Images,
  Models,
  Moderations,
  Responses,
} from "openai/resources";
import { SecureClient, type TransportMode } from "./secure-client.js";
import { type VerificationDocument } from "./verifier.js";
import { isRealBrowser } from "./env.js";

function createAsyncProxy<T extends object>(promise: Promise<T>): T {
  return new Proxy({} as T, {
    get(target, prop) {
      return new Proxy(() => {}, {
        get(_, nestedProp) {
          return (...args: any[]) =>
            promise.then((obj) => {
              const value = (obj as any)[prop][nestedProp];
              return typeof value === "function"
                ? value.apply((obj as any)[prop], args)
                : value;
            });
        },
        apply(_, __, args) {
          return promise.then((obj) => {
            const value = (obj as any)[prop];
            return typeof value === "function" ? value.apply(obj, args) : value;
          });
        },
      });
    },
  });
}

/**
 * Configuration options for TinfoilAI client.
 * 
 * @example
 * ```typescript
 * // Server-side with API key
 * const client = new TinfoilAI({ apiKey: "your-api-key" });
 * 
 * // Browser with bearer token (from your auth system)
 * const client = new TinfoilAI({ bearerToken: "your-jwt-token" });
 * 
 * // With custom transport mode
 * const client = new TinfoilAI({ apiKey: "key", transport: "tls" });
 * ```
 */
export interface TinfoilAIOptions {
  /** 
   * Tinfoil API key. Get one at https://docs.tinfoil.sh/get-api-key
   * In Node.js, defaults to TINFOIL_API_KEY environment variable.
   * Never use in browser code - use bearerToken instead.
   */
  apiKey?: string;
  
  /** 
   * Bearer token for browser authentication (e.g., JWT from your auth system).
   * Automatically enables browser usage without dangerouslyAllowBrowser.
   */
  bearerToken?: string;
  
  /** 
   * Override the base URL for API requests. 
   * Useful for proxying requests through your own backend.
   * @see https://docs.tinfoil.sh/guides/proxy-server
   */
  baseURL?: string;

  /**
   * Explicit enclave URL.
   * Use this when connecting to a custom enclave rather than the default routers.
   */
  enclaveURL?: string;
  
  /** GitHub repo for code verification. Defaults to tinfoilsh/confidential-model-router. */
  configRepo?: string;

  /**
   * Transport mode for secure communication.
   * - 'ehbp': HPKE encryption via EHBP protocol (default)
   * - 'tls': TLS certificate pinning
   * @default 'ehbp'
   */
  transport?: TransportMode;

  /** URL to fetch the attestation bundle from. */
  attestationBundleURL?: string;
  
  /** Additional OpenAI client options (passed through to underlying client) */
  [key: string]: any;
}

/**
 * Secure OpenAI-compatible client for Tinfoil's verifiably private AI inference.
 * 
 * TinfoilAI automatically verifies you're connected to a genuine secure enclave
 * and encrypts all requests end-to-end. The API is fully compatible with OpenAI's client.
 * 
 * @example
 * ```typescript
 * import { TinfoilAI } from "tinfoil";
 * 
 * const client = new TinfoilAI({
 *   apiKey: "your-api-key", // or use TINFOIL_API_KEY env var
 * });
 * 
 * const completion = await client.chat.completions.create({
 *   messages: [{ role: "user", content: "Hello!" }],
 *   model: "llama3-3-70b",
 * });
 * ```
 * 
 * @see https://docs.tinfoil.sh/sdk/javascript-sdk - Full documentation
 * @see https://docs.tinfoil.sh/cc/how-it-works - How verification works
 */
export class TinfoilAI {
  private client?: OpenAI;
  private secureClient: SecureClient;
  private openAIOptions: Record<string, any>;

  constructor(options: TinfoilAIOptions = {}) {
    const openAIOptions: Record<string, any> = { ...options };

    // In browser builds, never read secrets from process.env to avoid
    // leaking credentials into client bundles. Require explicit apiKey or bearerToken.
    if (options.bearerToken) {
      openAIOptions.apiKey = options.bearerToken;
      openAIOptions.dangerouslyAllowBrowser = true;
    } else if (options.apiKey) {
      openAIOptions.apiKey = options.apiKey;
    } else if (!isRealBrowser() && typeof process !== 'undefined' && process.env.TINFOIL_API_KEY) {
      openAIOptions.apiKey = process.env.TINFOIL_API_KEY;
    }

    if ((options as any).dangerouslyAllowBrowser === true) {
      openAIOptions.dangerouslyAllowBrowser = true;
    }

    this.openAIOptions = openAIOptions;

    this.secureClient = new SecureClient({
      baseURL: options.baseURL,
      enclaveURL: options.enclaveURL,
      configRepo: options.configRepo,
      transport: options.transport,
      attestationBundleURL: options.attestationBundleURL,
    });
  }

  /**
   * Wait for the client to complete verification and be ready for requests.
   * 
   * All API methods (chat, audio, etc.) call this automatically — you only 
   * need this for UI loading states during verification.
   * 
   * @example
   * ```typescript
   * const client = new TinfoilAI({ bearerToken: jwt });
   * await client.ready(); // Show spinner while verifying
   * ```
   */
  public async ready(): Promise<void> {
    await this.ensureReady();
  }

  private async ensureReady(): Promise<OpenAI> {
    await this.secureClient.ready();
    if (!this.client) {
      this.client = new OpenAI({
        ...this.openAIOptions,
        baseURL: this.secureClient.getBaseURL(),
        fetch: this.secureClient.fetch,
      });
    }
    return this.client;
  }

  /**
   * Get the verification document containing attestation details.
   * 
   * The document includes information about the enclave, code measurements,
   * and the status of each verification step.
   * 
   * @returns The verification document with attestation results
   * @throws Error if verification has not completed
   * 
   * @example
   * ```typescript
   * const doc = await client.getVerificationDocument();
   * console.log(doc.securityVerified); // true if all checks passed
   * console.log(doc.steps); // { fetchDigest, verifyCode, verifyEnclave, compareMeasurements }
   * ```
   * 
   * @see https://docs.tinfoil.sh/verification/attestation-architecture
   */
  public async getVerificationDocument(): Promise<VerificationDocument> {
    await this.ready();
    return this.secureClient.getVerificationDocument();
  }

  get chat(): Chat {
    return createAsyncProxy(this.ensureReady().then((client) => client.chat));
  }

  get files(): Files {
    return createAsyncProxy(this.ensureReady().then((client) => client.files));
  }

  get fineTuning(): FineTuning {
    return createAsyncProxy(
      this.ensureReady().then((client) => client.fineTuning),
    );
  }

  get images(): Images {
    return createAsyncProxy(this.ensureReady().then((client) => client.images));
  }

  get audio(): Audio {
    return createAsyncProxy(this.ensureReady().then((client) => client.audio));
  }

  get responses(): Responses {
    return createAsyncProxy(
      this.ensureReady().then((client) => client.responses),
    );
  }

  get embeddings(): Embeddings {
    return createAsyncProxy(
      this.ensureReady().then((client) => client.embeddings),
    );
  }

  get models(): Models {
    return createAsyncProxy(this.ensureReady().then((client) => client.models));
  }

  get moderations(): Moderations {
    return createAsyncProxy(
      this.ensureReady().then((client) => client.moderations),
    );
  }

  get beta(): Beta {
    return createAsyncProxy(this.ensureReady().then((client) => client.beta));
  }
}

// Namespace declaration merge to add OpenAI types to TinfoilAI
// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace TinfoilAI {
  export import Chat = OpenAI.Chat;
  export import Audio = OpenAI.Audio;
  export import Beta = OpenAI.Beta;
  export import Batches = OpenAI.Batches;
  export import Completions = OpenAI.Completions;
  export import Embeddings = OpenAI.Embeddings;
  export import Files = OpenAI.Files;
  export import FineTuning = OpenAI.FineTuning;
  export import Images = OpenAI.Images;
  export import Models = OpenAI.Models;
  export import Moderations = OpenAI.Moderations;
  export import Responses = OpenAI.Responses;
  export import Uploads = OpenAI.Uploads;
  export import VectorStores = OpenAI.VectorStores;
}