import { NONCE_SIZE } from "./document.js";
import { UsageError } from "./errors.js";
import { hex } from "./encoding.js";
export const MAX_ATTESTATION_DOCUMENT_BYTES = 32 * 1024 * 1024;
export interface FetchAttestationOptions {
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal;
}
/** Network acquisition only. Returned bytes remain untrusted until verified. */
export async function fetchAttestationDocument(
  endpoint: string,
  nonce: Uint8Array,
  options: FetchAttestationOptions = {},
): Promise<Uint8Array> {
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_SIZE)
    throw new UsageError("Expected nonce must contain 32 bytes");
  let url: URL;
  try {
    url = new URL(endpoint);
    if (url.protocol !== "https:" || url.username || url.password)
      throw new Error("HTTPS endpoint required");
  } catch (cause) {
    throw new UsageError("Invalid attestation endpoint", { cause });
  }
  url.pathname = "/.well-known/tinfoil-attestation";
  url.search = "";
  url.hash = "";
  url.searchParams.set("nonce", hex(nonce));
  const response = await (options.fetch ?? globalThis.fetch)(url, {
    signal: options.signal,
    redirect: "error",
    cache: "no-store",
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new Error(`Attestation fetch returned HTTP ${response.status}`);
  }
  if (Number(response.headers.get("content-length")) > MAX_ATTESTATION_DOCUMENT_BYTES) {
    await response.body?.cancel().catch(() => {});
    throw new Error("Attestation document exceeds size limit");
  }
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  try {
    const chunks: Uint8Array[] = [];
    let length = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_ATTESTATION_DOCUMENT_BYTES)
        throw new Error("Attestation document exceeds size limit");
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    try { await reader.cancel(); } catch { /* Preserve the read failure. */ }
    reader.releaseLock();
  }
}
