import OpenAI, { type ClientOptions as OpenAIClientOptions } from "openai";
import type { OpenAIRealtimeWS } from "openai/realtime/ws";
import type * as WS from "ws";
import { Client, type ClientOptions } from "./client.js";
import { Gateway, type GatewayOptions } from "./gateway.js";
import { ConfigurationError } from "./errors.js";
import type { VerificationSnapshot } from "./secure-client.js";
import { isRealBrowser } from "./env.js";

export type TinfoilAIOptions = Omit<OpenAIClientOptions, "fetch" | "baseURL"> & ClientOptions & {
  bearerToken?: string;
  gateway?: GatewayOptions & { url: string };
};

/** Native OpenAI resources and APIPromises using the SDK's verified request hook. */
export class TinfoilAI extends OpenAI {
  readonly #secure: Client | Gateway;
  constructor(options: TinfoilAIOptions = {}) {
    const { enclaveURL, configRepo, baseURL, transport, verification, acquisition, discoveryURL, userCacheSecret, bearerToken, gateway, ...provider } = options;
    if (gateway && [enclaveURL, configRepo, baseURL, transport].some(value => value !== undefined)) throw new ConfigurationError("Gateway configuration owns endpoints, repositories and EHBP transport");
    const secure = gateway
      ? new Gateway(gateway.url, { verification, acquisition, userCacheSecret, ...gateway })
      : new Client({ enclaveURL, configRepo, baseURL, transport, verification, acquisition, discoveryURL, userCacheSecret });
    const apiKey = bearerToken || provider.apiKey || (!isRealBrowser() && typeof process !== "undefined" ? process.env.TINFOIL_API_KEY : undefined);
    if (!apiKey) throw new ConfigurationError("API key is required; provide apiKey, bearerToken or TINFOIL_API_KEY");
    super({ ...provider, maxRetries: provider.maxRetries ?? 0, apiKey, dangerouslyAllowBrowser: bearerToken ? true : provider.dangerouslyAllowBrowser, baseURL: secure.getBaseURL(), fetch: secure.fetch });
    this.#secure = secure;
  }
  async ready(model?: string): Promise<void> {
    if (this.#secure instanceof Gateway) await this.#secure.ready(model);
    else await this.#secure.ready();
  }
  inspect(): VerificationSnapshot | undefined { return this.#secure.inspect(); }
  async getSessionRecoveryToken() { return this.#secure.getSessionRecoveryToken(); }
  async openRealtime(props: { model: string; options?: WS.ClientOptions }): Promise<OpenAIRealtimeWS> {
    if (this.#secure instanceof Gateway) throw new ConfigurationError("Realtime WebSockets require a direct enclave client");
    const enclave = await this.#secure.selectedClient();
    const pinned = await enclave.getPinnedWebSocketOptions();
    const { createPinnedRealtimeWS } = await import("./realtime.js");
    return createPinnedRealtimeWS(props, { apiKey: this.apiKey as string, baseURL: enclave.getEnclaveBaseURL() }, pinned);
  }
}
// Preserve OpenAI's consumer-facing resource type namespace.
// eslint-disable-next-line @typescript-eslint/no-namespace -- OpenAI resource types merge with the client class.
export namespace TinfoilAI {
  export import Chat = OpenAI.Chat;
  export import Audio = OpenAI.Audio;
  export import Beta = OpenAI.Beta;
  export import Batches = OpenAI.Batches;
  export import Completions = OpenAI.Completions;
  export import Decisions = OpenAI.Decisions;
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
