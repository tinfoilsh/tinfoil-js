/**
 * The EHBP transport mode: request and response bodies are sealed to the
 * attested HPKE key, so they stay private through a proxy. The method, URL
 * and headers aren't sealed, and neither is a request without a body or its
 * response. A protocol upgrade or a CONNECT tunnel is refused, because
 * nothing after the handshake would be sealed. A request body is sealed as
 * framed chunks and sent in full before the response begins, so a streaming
 * request body is accepted but its response cannot interleave with it.
 * This mode works wherever fetch does, browsers included.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { Identity, PROTOCOL, type RequestContext } from "ehbp";
import { AttestationError, ConfigurationError, messageOf, NetworkError } from "../../errors.js";
import type { Fetch } from "../../options.js";
import { PeerLacksKeyError, shapeOf, type BoundFetch, type Mode, type RequestShape } from "./transport.js";

/** How the sealed requests are sent; undefined selects the runtime's fetch. */
export interface EHBPOptions {
  readonly fetch?: Fetch;
}

const TUNNEL =
  "EHBP seals only request and response bodies, so it can't protect a protocol upgrade, such as a WebSocket, or a CONNECT tunnel; use the TLS transport mode on a direct connection";

/** Headers the protocol owns; a caller setting one would be overwritten or break framing. */
const RESERVED_HEADERS = ["content-length", "transfer-encoding", "host", PROTOCOL.ENCAPSULATED_KEY_HEADER.toLowerCase(), PROTOCOL.RESPONSE_NONCE_HEADER.toLowerCase()];

const MAX_PROBLEM_BYTES = 64 * 1024;

/**
 * Rejects a request whose traffic continues outside the bodies EHBP seals:
 * a protocol upgrade, such as a WebSocket, or a CONNECT tunnel. Sending one
 * would look protected while nothing after the handshake is.
 */
export function checkEHBP(request: RequestShape): void {
  if (request.method === "CONNECT" || request.headers.has("upgrade")) throw new ConfigurationError(TUNNEL);
}

/** A mode that seals bodies to the HPKE key the current verification attests and sends them with `options.fetch`. */
export function ehbpMode(options: EHBPOptions = {}): Mode {
  const send: Fetch = options.fetch ?? ((input, init) => fetch(input, init));
  return {
    name: "ehbp",
    validateRequest: checkEHBP,
    async bind(v: Verification): Promise<BoundFetch> {
      const key = v.hpkePublicKey();
      if (key === undefined) throw new AttestationError("document endorses no HPKE key; cannot use the EHBP transport mode (use the TLS transport mode)");
      let identity: Identity;
      try {
        identity = await Identity.fromPublicKeyHex(key);
      } catch (err) {
        throw new AttestationError(`failed to parse HPKE public key: ${messageOf(err)}`, { cause: err });
      }
      return { fetch: (input, init) => sealedFetch(identity, send, input, init) };
    },
  };
}

/**
 * Seals the request body to `identity`, sends it, and decrypts the response
 * chunk by chunk. A bodyless request passes through unsealed and its
 * response is plaintext. A peer that no longer holds the key answers with
 * a key-configuration problem, reported as the peer lacking the key.
 */
async function sealedFetch(identity: Identity, send: Fetch, input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const shape = shapeOf(input, init);
  checkEHBP(shape);
  const hasInitBody = init?.body !== undefined && init?.body !== null;
  if ((shape.method === "GET" || shape.method === "HEAD") && hasInitBody) {
    throw new ConfigurationError(`request with ${shape.method} method cannot have a body`);
  }
  for (const name of RESERVED_HEADERS) {
    if (shape.headers.has(name)) throw new ConfigurationError(`reserved request header cannot be set by callers: ${name}`);
  }
  // A stream body needs the half-duplex marker to become a Request; it is harmless otherwise.
  const request = new Request(input, { ...init, duplex: "half" } as RequestInit);

  let sealed: { request: Request; context: RequestContext | null; cleanup?: () => Promise<void> };
  try {
    sealed = await identity.encryptRequestWithContext(request);
  } catch (err) {
    throw new NetworkError(`failed to seal the request: ${messageOf(err)}`, { cause: err });
  }
  if (sealed.context === null) return send(sealed.request);

  let response: Response;
  try {
    response = await send(sealed.request);
  } finally {
    // The response headers mean the upload finished; what the sealing spooled is done.
    await sealed.cleanup?.().catch(() => {});
  }
  await rejectKeyMismatch(response);
  if (response.headers.has(PROTOCOL.RESPONSE_NONCE_HEADER)) {
    try {
      return await identity.decryptResponseWithContext(response, sealed.context);
    } catch (err) {
      await response.body?.cancel().catch(() => {});
      throw new NetworkError(`failed to open the response: ${messageOf(err)}`, { cause: err });
    }
  }
  // An error status may come from a proxy or from the peer before it could seal.
  if (!response.ok) return response;
  await response.body?.cancel().catch(() => {});
  throw new NetworkError(`sealed exchange answered without the ${PROTOCOL.RESPONSE_NONCE_HEADER} header`);
}

/** A 422 problem-details response naming the key-configuration problem means the peer no longer holds the key. */
async function rejectKeyMismatch(response: Response): Promise<void> {
  if (response.status !== 422 || !isProblemJSON(response.headers.get("content-type"))) return;
  let problem: { type?: unknown; title?: unknown } | undefined;
  try {
    const bytes = await readBounded(response.clone(), MAX_PROBLEM_BYTES);
    if (bytes === undefined) return;
    problem = JSON.parse(new TextDecoder().decode(bytes)) as { type?: unknown; title?: unknown };
  } catch {
    return;
  }
  if (problem?.type !== PROTOCOL.KEY_CONFIG_PROBLEM_TYPE) return;
  await response.body?.cancel().catch(() => {});
  throw new PeerLacksKeyError(typeof problem.title === "string" ? problem.title : "key configuration mismatch; re-verify the enclave");
}

function isProblemJSON(contentType: string | null): boolean {
  if (contentType === null) return false;
  return contentType.split(";", 1)[0]!.trim().toLowerCase() === PROTOCOL.PROBLEM_JSON_MEDIA_TYPE;
}

/** The body up to `limit` bytes, or undefined when it is larger or absent. */
async function readBounded(response: Response, limit: number): Promise<Uint8Array | undefined> {
  if (response.body === null) return undefined;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      return undefined;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
