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
import type { VerificationDocument } from "./verifier.js";
import { TINFOIL_CONFIG } from "./config.js";
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

interface TinfoilAIOptions {
  apiKey?: string;
  bearerToken?: string;
  baseURL?: string;
  enclaveURL?: string;
  configRepo?: string;
  transport?: TransportMode;
  [key: string]: any; // Allow other OpenAI client options
}

export class TinfoilAI {
  private client?: OpenAI;
  private clientPromise: Promise<OpenAI>;
  private readyPromise?: Promise<void>;
  private configRepo?: string;
  private secureClient: SecureClient;
  private verificationDocument?: VerificationDocument;
  private useBearerToken: boolean;

  public apiKey?: string;
  public bearerToken?: string;
  public baseURL?: string;
  public enclaveURL?: string;

  constructor(options: TinfoilAIOptions = {}) {
    const openAIOptions = { ...options };

    // bearerToken is used for browser auth (e.g., JWT from your auth system)
    // It automatically enables browser usage without dangerouslyAllowBrowser
    this.useBearerToken = !!options.bearerToken;

    // In browser builds, never read secrets from process.env to avoid
    // leaking credentials into client bundles. Require explicit apiKey or bearerToken.
    if (options.bearerToken) {
      openAIOptions.apiKey = options.bearerToken;
      this.bearerToken = options.bearerToken;
    } else if (options.apiKey) {
      openAIOptions.apiKey = options.apiKey;
    } else if (!isRealBrowser() && process.env.TINFOIL_API_KEY) {
      openAIOptions.apiKey = process.env.TINFOIL_API_KEY;
    }

    this.apiKey = options.apiKey;
    this.baseURL = options.baseURL;
    this.enclaveURL = options.enclaveURL;
    this.configRepo = options.configRepo || TINFOIL_CONFIG.INFERENCE_PROXY_REPO;

    this.secureClient = new SecureClient({
      baseURL: this.baseURL,
      enclaveURL: this.enclaveURL,
      configRepo: this.configRepo,
      transport: options.transport,
    });

    this.clientPromise = this.createOpenAIClient(openAIOptions);
  }

  public async ready(): Promise<void> {
    if (!this.readyPromise) {
      this.readyPromise = (async () => {
        this.client = await this.clientPromise;
      })();
    }
    return this.readyPromise;
  }

  private async createOpenAIClient(
    options: Partial<
      Omit<ConstructorParameters<typeof OpenAI>[0], "baseURL">
    > = {},
  ): Promise<OpenAI> {
    await this.secureClient.ready();
    
    this.verificationDocument = await this.secureClient.getVerificationDocument();
    if (!this.verificationDocument) {
      throw new Error("Verification document not available after successful verification");
    }

    // Use the provided baseURL, or get it from SecureClient after initialization
    const baseURL = this.baseURL || this.secureClient.getBaseURL();

    const clientOptions: ConstructorParameters<typeof OpenAI>[0] = {
      ...options,
      baseURL: baseURL,
      fetch: this.secureClient.fetch,
    };

    // Automatically allow browser usage when bearerToken is used (e.g., JWT auth)
    // or when explicitly requested via dangerouslyAllowBrowser
    if (this.useBearerToken || (options as any).dangerouslyAllowBrowser === true) {
      clientOptions.dangerouslyAllowBrowser = true;
    }

    return new OpenAI(clientOptions);
  }

  private async ensureReady(): Promise<OpenAI> {
    await this.ready();
    return this.client!;
  }

  public async getVerificationDocument(): Promise<VerificationDocument> {
    await this.ready();
    if (!this.verificationDocument) {
      throw new Error("Verification document unavailable: client not verified yet");
    }
    return this.verificationDocument;
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