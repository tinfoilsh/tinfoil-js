/**
 * A local EHBP server for tests: it opens sealed request bodies with its
 * identity's private key and seals response chunks under the exchange's
 * derived keys, writing each chunk as its own frame as the route yields it.
 * Routes decide the status, headers and body; a route can answer in
 * plaintext even to a sealed request (as an error path would).
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
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

export interface EhbpServer {
  readonly origin: string;
  readonly publicKeyHex: string;
  readonly identity: Identity;
  readonly seen: Seen[];
  close(): Promise<void>;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export async function startEhbpServer(route: (seen: Seen) => Reply | Promise<Reply>): Promise<EhbpServer> {
  const identity = await Identity.generate();
  const publicKeyHex = await identity.getPublicKeyHex();
  const suite = identity["suite"];
  const seen: Seen[] = [];

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      void (async () => {
        const raw = new Uint8Array(Buffer.concat(chunks));
        const encHex = req.headers[PROTOCOL.ENCAPSULATED_KEY_HEADER.toLowerCase()];
        let ctx: RecipientContext | undefined;
        let enc: Uint8Array | undefined;
        let body: Uint8Array = raw;
        if (typeof encHex === "string") {
          enc = hexToBytes(encHex);
          const recipient: RecipientContext = await suite.SetupRecipient(identity.getPrivateKey(), enc, { info: utf8(HPKE_REQUEST_INFO) });
          ctx = recipient;
          try {
            body = await openFrames(recipient, raw);
          } catch {
            res.writeHead(422, { "content-type": PROTOCOL.PROBLEM_JSON_MEDIA_TYPE });
            res.end(JSON.stringify({ type: PROTOCOL.KEY_CONFIG_PROBLEM_TYPE, title: "key configuration mismatch" }));
            return;
          }
        }
        const request: Seen = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body, sealed: ctx !== undefined };
        seen.push(request);
        const reply = await route(request);
        const headers: Record<string, string> = { ...reply.headers };
        if (ctx === undefined || enc === undefined || reply.plaintext) {
          res.writeHead(reply.status ?? 200, headers);
          for await (const chunk of chunksOf(reply.body)) res.write(Buffer.from(chunk));
          res.end();
          return;
        }
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const secret = new Uint8Array(await ctx.Export(utf8(EXPORT_LABEL), EXPORT_LENGTH));
        const km = await deriveResponseKeys(secret, enc, nonce);
        headers[PROTOCOL.RESPONSE_NONCE_HEADER] = bytesToHex(nonce);
        res.writeHead(reply.status ?? 200, headers);
        let seq = 0;
        for await (const chunk of chunksOf(reply.body)) {
          const sealed = await encryptChunk(km, seq++, chunk);
          const frame = new Uint8Array(4 + sealed.length);
          new DataView(frame.buffer).setUint32(0, sealed.length, false);
          frame.set(sealed, 4);
          res.write(Buffer.from(frame));
        }
        res.end();
      })().catch((err: unknown) => {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end(String(err));
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    origin,
    publicKeyHex,
    identity,
    seen,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
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
export async function* paced(chunks: string[], delayMs: number): AsyncGenerator<Uint8Array> {
  for (const [i, chunk] of chunks.entries()) {
    if (i > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
    yield utf8(chunk);
  }
}
