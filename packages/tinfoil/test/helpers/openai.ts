/** An OpenAI client over an attested HTTP client that a factory is creating, as a caller builds one. */
import { OpenAIClient, type AttestedHTTPClient, type OpenAIClientOptions, type OpenAIOptions } from "../../src/openai-client.js";

/** `new OpenAIClient(await http, options, openaiOptions)`. */
export async function openAIOver<H extends AttestedHTTPClient>(http: Promise<H>, openaiOptions?: OpenAIClientOptions, options?: OpenAIOptions): Promise<OpenAIClient<H>> {
  return new OpenAIClient(await http, options, openaiOptions);
}
