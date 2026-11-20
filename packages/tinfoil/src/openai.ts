/**
 * The `tinfoil/openai` entry: the OpenAI-compatible client over the attested
 * HTTP clients, the one-line client for Tinfoil's recommended route, realtime
 * sessions, and the OpenAI helpers and error types that callers need
 * alongside them. It is its own entry, with `openai` an optional peer
 * dependency, so that callers who use only the HTTP clients don't need the
 * OpenAI library. Like `tinfoil/ai-sdk`, it has no `browser` condition: the
 * package's browser field substitutes the internal modules that differ.
 */
export { OpenAIClient, createClient, type AttestedHTTPClient, type OpenAIOptions, type OpenAIClientOptions } from "./openai-client.js";
export { createRealtimeWebSocket } from "./realtime.js";
export type { RealtimeOptions } from "./options.js";

export {
  type Uploadable,
  toFile,
  APIPromise,
  PagePromise,
  OpenAIError,
  APIError,
  APIConnectionError,
  APIConnectionTimeoutError,
  APIUserAbortError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  BadRequestError,
  AuthenticationError,
  InternalServerError,
  PermissionDeniedError,
  UnprocessableEntityError,
} from "openai";
