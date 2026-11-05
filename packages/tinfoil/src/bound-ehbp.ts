import { Identity, PROTOCOL, KeyConfigMismatchError, ProtocolError, DecryptionError, RESPONSE_NONCE_LENGTH, extractSessionRecoveryToken, decryptResponseWithToken, type SessionRecoveryToken } from "ehbp";
import { AttestationError, ConfigurationError } from "./errors.js";

/** A fixed attested identity and its request sessions; no discovery or recovery. */
export class BoundEHBPTransport {
  readonly #identity: Identity;
  #generation = 0;
  #token?: SessionRecoveryToken;
  constructor(identity: Identity) { this.#identity = identity; }
  async request(request: Request): Promise<Response> {
    const generation = ++this.#generation;
    this.#token = undefined;
    const encrypted = await this.#identity.encryptRequestWithContext(request);
    const token = encrypted.context ? await extractSessionRecoveryToken(encrypted.context) : undefined;
    const response = await globalThis.fetch(encrypted.request);
    if (!token) return response;
    try {
      const nonce = response.headers.get(PROTOCOL.RESPONSE_NONCE_HEADER);
      if (nonce === null) {
        await checkKeyRejection(response);
        if (!response.ok) return response;
        throw new AttestationError("EHBP success response omitted its authentication nonce");
      }
      if (!new RegExp(`^[0-9a-fA-F]{${RESPONSE_NONCE_LENGTH * 2}}$`).test(nonce)) throw new AttestationError("EHBP response nonce is malformed");
      let finished = false;
      const clear = () => { finished = true; if (this.#generation === generation) this.#token = undefined; };
      const decrypted = await decryptResponseWithToken(response, token, clear, clear);
      if (!finished && generation === this.#generation) this.#token = token;
      if (!decrypted.body) return decrypted;
      // Stream authentication failures cross the same SDK error boundary as headers.
      const reader = decrypted.body.getReader();
      const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
          try { const { done, value } = await reader.read(); if (done) { reader.releaseLock(); controller.close(); } else controller.enqueue(value); }
          catch (cause) { reader.releaseLock(); controller.error(authenticationError(cause)); }
        },
        async cancel(reason) { try { await reader.cancel(reason); } finally { reader.releaseLock(); } },
      });
      return new Response(body, { status: decrypted.status, statusText: decrypted.statusText, headers: decrypted.headers });
    } catch (cause) {
      try { await response.body?.cancel(); } catch { /* Preserve the binding failure. */ }
      throw authenticationError(cause);
    }
  }
  async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
    if (!this.#token) throw new ConfigurationError("No live EHBP response session is available");
    return { exportedSecret: this.#token.exportedSecret.slice(), requestEnc: this.#token.requestEnc.slice() };
  }
}
function authenticationError(cause: unknown): unknown {
  if (cause instanceof ProtocolError || cause instanceof DecryptionError) return new AttestationError("EHBP response authentication failed", { cause });
  return cause;
}
async function checkKeyRejection(response: Response): Promise<void> {
  if (response.status !== 422 || response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !== PROTOCOL.PROBLEM_JSON_MEDIA_TYPE) return;
  const reader = response.clone().body?.getReader();
  if (!reader) return;
  const chunks: Uint8Array[] = []; let length = 0;
  let problem: unknown;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      length += value.byteLength; if (length > 32 * 1024) return;
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    try { problem = JSON.parse(new TextDecoder().decode(bytes)); } catch { return; }
  } finally {
    // A tee branch can wait for the consumer of the other branch; do not deadlock it.
    void reader.cancel().catch(() => {}); reader.releaseLock();
  }
  if (problem && typeof problem === "object" && (problem as { type?: unknown }).type === PROTOCOL.KEY_CONFIG_PROBLEM_TYPE) {
    const title = (problem as { title?: unknown }).title;
    throw new KeyConfigMismatchError(typeof title === "string" ? title : undefined);
  }
}
