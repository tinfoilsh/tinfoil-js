/**
 * The EHBP peer's side of the protocol for tests, on WebCrypto alone so it
 * runs in browsers as well as Node: it opens sealed request bodies with the
 * peer identity's private key and seals response chunks under the
 * exchange's derived keys, one frame per chunk as the route yields it.
 * Routes decide the status, headers and body; a route can answer in
 * plaintext even to a sealed request (as an error path would).
 */
import { bytesToHex, deriveResponseKeys, encryptChunk, EXPORT_LABEL, EXPORT_LENGTH, hexToBytes, HPKE_REQUEST_INFO, Identity, PROTOCOL, type RecipientContext } from "ehbp";

export interface Seen {
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string | string[] | undefined>;
  /** The request body, opened when it was sealed. */
  readonly body: Uint8Array;
  readonly sealed: boolean;
}

export interface Reply {
  readonly status?: number;
  readonly headers?: Record<string, string>;
  /** Chunks of an iterable become one sealed frame each, written as produced. */
  readonly body?: string | Uint8Array | AsyncIterable<Uint8Array>;
  /** Answer unsealed even when the request was sealed. */
  readonly plaintext?: boolean;
}

/** A response as the peer produces it: the status, headers, and body chunks to write in order. */
export interface Produced {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly chunks: AsyncIterable<Uint8Array>;
}

export interface EhbpPeer {
  readonly publicKeyHex: string;
  readonly identity: Identity;
  readonly seen: Seen[];
  /** Answers one request: `encHex` is the encapsulated-key header when the body is sealed. */
  respond(method: string, path: string, headers: Record<string, string | string[] | undefined>, raw: Uint8Array, encHex: string | undefined): Promise<Produced>;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export async function createEhbpPeer(route: (seen: Seen) => Reply | Promise<Reply>): Promise<EhbpPeer> {
  const identity = await Identity.generate();
  const publicKeyHex = await identity.getPublicKeyHex();
  const suite = identity["suite"];
  const seen: Seen[] = [];
  return {
    publicKeyHex,
    identity,
    seen,
    respond: async (method, path, headers, raw, encHex) => {
      let ctx: RecipientContext | undefined;
      let enc: Uint8Array | undefined;
      let body: Uint8Array = raw;
      if (encHex !== undefined) {
        enc = hexToBytes(encHex);
        const recipient: RecipientContext = await suite.SetupRecipient(identity.getPrivateKey(), enc, { info: utf8(HPKE_REQUEST_INFO) });
        ctx = recipient;
        try {
          body = await openFrames(recipient, raw);
        } catch {
          return {
            status: 422,
            headers: { "content-type": PROTOCOL.PROBLEM_JSON_MEDIA_TYPE },
            chunks: chunksOf(JSON.stringify({ type: PROTOCOL.KEY_CONFIG_PROBLEM_TYPE, title: "key configuration mismatch" })),
          };
        }
      }
      const request: Seen = { method, path, headers, body, sealed: ctx !== undefined };
      seen.push(request);
      const reply = await route(request);
      const replyHeaders: Record<string, string> = { ...reply.headers };
      if (ctx === undefined || enc === undefined || reply.plaintext) {
        return { status: reply.status ?? 200, headers: replyHeaders, chunks: chunksOf(reply.body) };
      }
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const secret = new Uint8Array(await ctx.Export(utf8(EXPORT_LABEL), EXPORT_LENGTH));
      const km = await deriveResponseKeys(secret, enc, nonce);
      replyHeaders[PROTOCOL.RESPONSE_NONCE_HEADER] = bytesToHex(nonce);
      return { status: reply.status ?? 200, headers: replyHeaders, chunks: sealedFrames(km, chunksOf(reply.body)) };
    },
  };
}

/** The peer as a `fetch` at `origin`, for runtimes where no server can listen. */
export function fetchOf(peer: EhbpPeer): (input: string | URL | Request, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const request = new Request(input, init);
    const headers: Record<string, string> = {};
    request.headers.forEach((value, name) => (headers[name] = value));
    const raw = new Uint8Array(await request.arrayBuffer());
    const url = new URL(request.url);
    const produced = await peer.respond(request.method, url.pathname + url.search, headers, raw, headers[PROTOCOL.ENCAPSULATED_KEY_HEADER.toLowerCase()]);
    const iterator = produced.chunks[Symbol.asyncIterator]();
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        const next = await iterator.next();
        if (next.done) controller.close();
        else controller.enqueue(next.value);
      },
      cancel: () => void iterator.return?.(),
    });
    // A status that forbids a body takes none, as a server's response would carry none.
    const body = [204, 205, 304].includes(produced.status) ? null : stream;
    return new Response(body, { status: produced.status, headers: produced.headers });
  };
}

async function* sealedFrames(km: Awaited<ReturnType<typeof deriveResponseKeys>>, chunks: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
  let seq = 0;
  for await (const chunk of chunks) {
    const sealed = await encryptChunk(km, seq++, chunk);
    const frame = new Uint8Array(4 + sealed.length);
    new DataView(frame.buffer).setUint32(0, sealed.length, false);
    frame.set(sealed, 4);
    yield frame;
  }
}

async function* chunksOf(body: Reply["body"]): AsyncGenerator<Uint8Array> {
  if (body === undefined) return;
  if (typeof body === "string") {
    yield utf8(body);
    return;
  }
  if (body instanceof Uint8Array) {
    yield body;
    return;
  }
  for await (const chunk of body) yield chunk;
}

/** Opens `[u32 length][sealed frame]...` into the plaintext it carries. */
async function openFrames(ctx: RecipientContext, raw: Uint8Array): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let offset = 0;
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  while (offset < raw.length) {
    const length = view.getUint32(offset, false);
    offset += 4;
    const sealed = raw.subarray(offset, offset + length);
    if (sealed.length !== length) throw new Error("truncated frame");
    offset += length;
    parts.push(new Uint8Array(await ctx.Open(sealed)));
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Yields `chunks` one by one, pausing `delayMs` between them, so a reader can observe them arriving separately. */
export async function* paced(chunks: string[], delayMs: number, onEnd?: () => void): AsyncGenerator<Uint8Array> {
  for (const [i, chunk] of chunks.entries()) {
    if (i > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
    yield utf8(chunk);
  }
  onEnd?.();
}
