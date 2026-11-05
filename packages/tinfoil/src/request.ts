import { ConfigurationError } from "./errors.js";
import { normalizeEncryptedBodyRequestArgs } from "./encrypted-body-fetch.js";

export interface PreparedRequest { url: URL; init: RequestInit; replayable: boolean }
/** Preserve Fetch override semantics and detach mutable in-memory request inputs. */
export function prepareRequest(input: RequestInfo | URL, init: RequestInit | undefined, baseURL: string, allowedOrigins: readonly string[] = [new URL(baseURL).origin]): PreparedRequest {
  const url = new URL(input instanceof Request ? input.url : String(input), baseURL);
  if (!allowedOrigins.includes(url.origin) || url.username || url.password) throw new ConfigurationError("Request destination differs from the configured HTTP origin");
  const normalized = normalizeEncryptedBodyRequestArgs(input, init);
  const options = { ...normalized.init, headers: new Headers(normalized.init?.headers) };
  if (options.body instanceof ArrayBuffer) options.body = options.body.slice(0);
  else if (ArrayBuffer.isView(options.body)) options.body = new Uint8Array(options.body.buffer, options.body.byteOffset, options.body.byteLength).slice();
  const replayable = options.body == null || typeof options.body === "string" || options.body instanceof ArrayBuffer || ArrayBuffer.isView(options.body) || options.body instanceof Blob || options.body instanceof URLSearchParams;
  if (options.body instanceof URLSearchParams) options.body = new URLSearchParams(options.body);
  return { url, init: options, replayable };
}
export function bodyText(body: BodyInit | null | undefined): string | undefined {
  if (typeof body === "string") return body;
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(body); } catch { return undefined; }
  }
  return undefined;
}
export async function discard(response: Response): Promise<void> { await response.body?.cancel(); }
