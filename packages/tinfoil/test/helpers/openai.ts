/** An OpenAI client over an attested HTTP client that a factory is creating, as a caller builds one. */
import { OpenAIClient, type AttestedHTTPClient, type OpenAIClientOptions } from "../../src/openai-client.js";

/** `new OpenAIClient(await http, options)`. */
export async function openAIOver<H extends AttestedHTTPClient>(http: Promise<H>, options?: OpenAIClientOptions): Promise<OpenAIClient<H>> {
  return new OpenAIClient(await http, options);
}
