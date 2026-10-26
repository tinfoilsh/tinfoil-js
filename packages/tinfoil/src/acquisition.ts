import { ConfigurationError, NetworkError } from "./errors.js";
import { SDK_NAME, SDK_VERSION } from "./version.js";

export interface AcquisitionOptions {
  /** Applied only to untrusted discovery and attestation acquisition. */
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  requestInit?: Omit<RequestInit, "body" | "method" | "signal">;
}
export const DEFAULT_NETWORK_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
export function httpURL(value: string, label: string, httpsOnly = false): URL {
  let url: URL;
  try { url = new URL(value); } catch (cause) { throw new ConfigurationError(`${label} must be an absolute HTTP(S) URL`, { cause }); }
  if ((url.protocol !== "https:" && (httpsOnly || url.protocol !== "http:")) || url.username || url.password || url.hash) {
    throw new ConfigurationError(`${label} must be ${httpsOnly ? "HTTPS" : "HTTP(S)"}, without credentials or fragment`);
  }
  return url;
}
export function copyAcquisitionOptions(options: AcquisitionOptions = {}): Readonly<AcquisitionOptions> {
  for (const value of [options.timeoutMs, options.maxResponseBytes]) {
    if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) throw new ConfigurationError("Acquisition limits must be positive safe integers");
  }
  return Object.freeze({ ...options, requestInit: options.requestInit && { ...options.requestInit, headers: new Headers(options.requestInit.headers) } });
}
/** A single bounded external call. The caller owns selection and retry policy. */
export async function acquireBytes(url: URL, options: AcquisitionOptions = {}, signal?: AbortSignal, extraHeaders?: HeadersInit): Promise<Uint8Array> {
  signal?.throwIfAborted();
  const controller = new AbortController();
  const abort = () => controller.abort(signal?.reason);
  signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(new DOMException("Acquisition deadline exceeded", "TimeoutError")), options.timeoutMs ?? DEFAULT_NETWORK_TIMEOUT_MS);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    const headers = new Headers(options.requestInit?.headers);
    headers.set("Tinfoil-SDK", SDK_NAME); headers.set("Tinfoil-SDK-Version", SDK_VERSION);
    new Headers(extraHeaders).forEach((value, key) => headers.set(key, value));
    const redirect = options.requestInit?.redirect ?? "error";
    let target = url;
    let response: Response;
    for (let redirects = 0; ; redirects++) {
      response = await (options.fetch ?? globalThis.fetch)(target, { ...options.requestInit, method: "GET", headers, signal: controller.signal, redirect: "manual" });
      if (![301, 302, 303, 307, 308].includes(response.status)) break;
      const location = response.headers.get("location");
      if (!location || redirect === "manual") break;
      await response.body?.cancel();
      if (redirect === "error") throw new NetworkError("Acquisition redirect rejected by configured policy");
      if (redirects >= 20) throw new NetworkError("Too many acquisition redirects");
      let next: URL;
      try { next = new URL(location, target); } catch (cause) { throw new NetworkError("Invalid acquisition redirect", { cause }); }
      if (next.protocol !== "https:" || next.username || next.password) throw new NetworkError("Acquisition redirect must use HTTPS without URL credentials");
      if (next.origin !== target.origin) {
        for (const name of ["authorization", "proxy-authorization", "cookie"]) headers.delete(name);
      }
      target = next;
    }
    if (!response.ok) { await response.body?.cancel(); throw new NetworkError(`Acquisition failed: HTTP ${response.status}`); }
    const limit = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    if (Number(response.headers.get("content-length")) > limit) { await response.body?.cancel(); throw new NetworkError("Acquisition response exceeds size limit"); }
    reader = response.body?.getReader();
    if (!reader) return new Uint8Array();
    const chunks: Uint8Array[] = []; let length = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new NetworkError("Acquisition response exceeds size limit");
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return bytes;
  } catch (cause) {
    if (signal?.aborted) throw signal.reason;
    if (cause instanceof NetworkError) throw cause;
    throw new NetworkError("Failed to acquire untrusted attestation or discovery material", { cause });
  } finally {
    clearTimeout(timer); signal?.removeEventListener("abort", abort);
    if (reader) { try { await reader.cancel(); } catch { /* Preserve the acquisition failure. */ } finally { reader.releaseLock(); } }
  }
}
export async function fetchAttestationDocument(endpoint: string, nonce: Uint8Array, options: AcquisitionOptions & { signal?: AbortSignal; relayURL?: string } = {}): Promise<Uint8Array> {
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32) throw new ConfigurationError("Attestation nonce must contain 32 bytes");
  const enclave = httpURL(endpoint, "enclaveURL", true);
  const source = options.relayURL ? httpURL(options.relayURL, "relayURL", true) : enclave;
  const url = new URL("/.well-known/tinfoil-attestation", source);
  url.searchParams.set("nonce", Array.from(nonce, b => b.toString(16).padStart(2, "0")).join(""));
  if (options.relayURL) url.searchParams.set("enclave", enclave.host);
  return acquireBytes(url, options, options.signal);
}
export async function fetchRouters(discoveryURL = "https://atc.tinfoil.sh/routers", options: AcquisitionOptions = {}): Promise<string[]> {
  const bytes = await acquireBytes(httpURL(discoveryURL, "discoveryURL", true), options);
  try {
    const routers: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (!Array.isArray(routers) || routers.length === 0 || routers.some(value => typeof value !== "string")) throw new Error("Expected nonempty router list");
    return routers.map(value => httpURL(value.includes("://") ? value : `https://${value}`, "router", true).origin);
  } catch (cause) { throw new NetworkError("Invalid router discovery response", { cause }); }
}
