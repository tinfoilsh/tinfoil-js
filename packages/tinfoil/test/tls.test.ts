/**
 * The TLS transport against a local HTTPS server: the pin on every
 * connection (a matching key serves, a mismatch fails in the handshake and
 * no request reaches the server), plaintext refused, response bodies
 * streamed chunk by chunk as the server writes them, request bodies
 * streamed as they are produced, a redirect handed back rather than
 * followed, a binding retired without cutting a request in flight, and the
 * replay after a key rotation.
 */
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, NetworkError } from "../src/errors.js";
import { Enclave } from "../src/internal/enclave.js";
import { withReplay } from "../src/internal/transport/replay.js";
import { tlsMode } from "../src/internal/transport/tls.js";
import { isKeyRejection, KeyedTransport, KeyRejectionError, PeerLacksKeyError, shapeOf, type BoundFetch } from "../src/internal/transport/transport.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, type Verification, type Verifier } from "../../verifier/src/index.js";

const cert = readFileSync(new URL("./fixtures/ws-test-cert.pem", import.meta.url));
const key = readFileSync(new URL("./fixtures/ws-test-key.pem", import.meta.url));
const PIN = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
const OTHER = "ab".repeat(32);

/** What the server saw: request paths, and when each streamed response ended. */
const seen: { path: string; method: string; bodyLength: number; headers: Record<string, string | string[] | undefined> }[] = [];
let server: Server;
let origin: string;
let sseEnded = false;
/** The TLS connections open right now, pooled ones included. */
let open = 0;
/** The TLS connections the server has accepted so far. */
let accepted = 0;
/** Called with each piece of a request body to `/echo` as the server receives it. */
let onEchoData: ((chunk: Buffer) => void) | undefined;

/** Resolves once `cond` holds, polling; fails after `ms`. */
async function until(cond: () => boolean, ms = 5_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function verification(fp: string): Verification {
  return {
    cryptoMaterial: [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: fp }],
    cryptoMaterialData: (id: string) => (id === "tls" ? fp : undefined),
    tlsPublicKeyFP: fp,
    hpkePublicKey: undefined,
    freshnessExpiresAt: new Date(Date.now() + 60_000),
  } as unknown as Verification;
}

beforeAll(async () => {
  server = createServer({ key, cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      chunks.push(c);
      if (req.url === "/echo") onEchoData?.(c);
    });
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      seen.push({ path: req.url ?? "", method: req.method ?? "", bodyLength: body.length, headers: req.headers });
      switch (req.url) {
        case "/sse": {
          sseEnded = false;
          res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
          let n = 0;
          const timer = setInterval(() => {
            n++;
            res.write(`data: chunk ${n}\n\n`);
            if (n === 3) {
              clearInterval(timer);
              res.end();
              sseEnded = true;
            }
          }, 60);
          break;
        }
        case "/echo":
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ length: body.length, contentType: req.headers["content-type"] ?? null }));
          break;
        case "/empty":
          res.writeHead(204);
          res.end();
          break;
        case "/redirect":
          res.writeHead(307, { location: `${origin}/plain` });
          res.end();
          break;
        default:
          res.writeHead(200, { "content-type": "text/plain", "x-two": "a", "set-cookie": ["a=1", "b=2"] });
          res.end("hello");
      }
    });
  });
  server.on("secureConnection", (socket) => {
    open++;
    accepted++;
    socket.once("close", () => open--);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `https://localhost:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("tlsMode", () => {
  const mode = tlsMode({ ca: cert });

  it("refuses plaintext before any network I/O and requires a TLS key to bind", async () => {
    expect(() => mode.validateRequest(shapeOf("http://localhost/"))).toThrow(ConfigurationError);
    expect(() => mode.validateRequest(shapeOf("https://localhost/"))).not.toThrow();
    await expect(mode.bind({ ...verification(PIN), tlsPublicKeyFP: undefined } as Verification)).rejects.toThrow(/endorses no "tls" key/);
    const bound = await mode.bind(verification(PIN));
    await expect(bound.fetch("http://localhost/")).rejects.toThrow(ConfigurationError);
    bound.close?.();
  });

  it("serves over a connection whose certificate carries the pinned key, with headers and status intact", async () => {
    const bound = await mode.bind(verification(PIN));
    const res = await bound.fetch(`${origin}/plain`, { headers: { "x-test": "1" } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("hello");
    expect(res.headers.get("x-two")).toBe("a");
    expect(res.headers.getSetCookie()).toEqual(["a=1", "b=2"]);
    expect(seen[seen.length - 1]?.headers["x-test"]).toBe("1");
    const empty = await bound.fetch(`${origin}/empty`);
    expect(empty.status).toBe(204);
    expect(empty.body).toBeNull();
    bound.close?.();
  });

  it("fails the handshake when the certificate carries another key, before the request is sent", async () => {
    const before = seen.length;
    const bound = await mode.bind(verification(OTHER));
    const err = await bound.fetch(`${origin}/never`).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PeerLacksKeyError);
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as Error).message).toBe("attestation error: enclave certificate does not match the attested key; re-verify the enclave");
    expect(seen.length).toBe(before);
    bound.close?.();
  });

  it("fails closed when the normal certificate check fails, as a peer lacking the key", async () => {
    const untrusting = await tlsMode().bind(verification(PIN));
    const err = await untrusting.fetch(`${origin}/never`).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PeerLacksKeyError);
    untrusting.close?.();
  });

  it("streams a response chunk by chunk as the server writes it", async () => {
    const bound = await mode.bind(verification(PIN));
    const res = await bound.fetch(`${origin}/sse`);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    const first = await reader.read();
    expect(first.done).toBe(false);
    expect(decoder.decode(first.value)).toContain("chunk 1");
    expect(sseEnded).toBe(false);
    let text = decoder.decode(first.value);
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value);
    }
    expect(text).toBe("data: chunk 1\n\ndata: chunk 2\n\ndata: chunk 3\n\n");
    expect(sseEnded).toBe(true);
    bound.close?.();
  });

  it("streams a request body as it is produced", async () => {
    const bound = await mode.bind(verification(PIN));
    const chunk = new Uint8Array(64 * 1024).fill(7);
    let pulled = 0;
    let received = 0;
    let receivedBeforeSecond = 0;
    let firstArrived!: () => void;
    const arrival = new Promise<void>((resolve) => (firstArrived = resolve));
    onEchoData = (c) => {
      received += c.length;
      firstArrived();
    };
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (pulled === 8) {
          controller.close();
          return;
        }
        // The second chunk is produced only once the server holds part of
        // the first, which a body sent only after the stream closes never
        // reaches; the wait is bounded so that case fails instead of hanging.
        if (pulled === 1) {
          let timer: NodeJS.Timeout | undefined;
          const bounded = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => reject(new Error("the server received nothing before the second chunk was due")), 5_000);
          });
          await Promise.race([arrival, bounded]).finally(() => clearTimeout(timer));
          receivedBeforeSecond = received;
        }
        pulled++;
        controller.enqueue(chunk);
      },
    });
    try {
      const res = await bound.fetch(`${origin}/echo`, { method: "POST", body, headers: { "content-type": "application/octet-stream" } });
      expect(await res.json()).toEqual({ length: 8 * chunk.length, contentType: "application/octet-stream" });
    } finally {
      onEchoData = undefined;
      bound.close?.();
    }
    expect(pulled).toBe(8);
    expect(receivedBeforeSecond).toBeGreaterThan(0);
    expect(receivedBeforeSecond).toBeLessThanOrEqual(chunk.length);
  });

  it("sends strings, bytes, blobs and form data with their content type", async () => {
    const bound = await mode.bind(verification(PIN));
    const echo = async (init: RequestInit): Promise<{ length: number; contentType: string | null }> => (await bound.fetch(`${origin}/echo`, { method: "POST", ...init })).json();
    expect(await echo({ body: "abc", headers: { "content-type": "text/plain" } })).toEqual({ length: 3, contentType: "text/plain" });
    expect(await echo({ body: new Uint8Array([1, 2]) })).toEqual({ length: 2, contentType: null });
    expect(await echo({ body: new Blob(["xyz"], { type: "text/x" }) })).toEqual({ length: 3, contentType: "text/x" });
    const form = new FormData();
    form.set("f", "v");
    const sent = await echo({ body: form });
    expect(sent.contentType).toMatch(/^multipart\/form-data; boundary=/);
    expect(sent.length).toBeGreaterThan(10);
    const viaRequest = await (await bound.fetch(new Request(`${origin}/echo`, { method: "POST", body: "req" }))).json();
    expect(viaRequest.length).toBe(3);
    bound.close?.();
  });

  it("stops a request when its signal aborts", async () => {
    const bound = await mode.bind(verification(PIN));
    const controller = new AbortController();
    const pending = bound.fetch(`${origin}/sse`, { signal: controller.signal });
    const res = await pending;
    controller.abort(new Error("enough"));
    await expect(res.text()).rejects.toThrow();
    const early = new AbortController();
    early.abort(new Error("already"));
    await expect(bound.fetch(`${origin}/plain`, { signal: early.signal })).rejects.toThrow(/already/);
    bound.close?.();
  });

  it("takes a Request input's own signal, and none when the init says null", async () => {
    const bound = await mode.bind(verification(PIN));
    const own = new Error("own signal");
    await expect(bound.fetch(new Request(`${origin}/plain`, { signal: AbortSignal.abort(own) }))).rejects.toBe(own);
    const res = await bound.fetch(new Request(`${origin}/plain`, { signal: AbortSignal.abort(own) }), { signal: null });
    expect(await res.text()).toBe("hello");
    bound.close?.();
  });

  it("refuses a request naming a Host of its own, before any network I/O", async () => {
    expect(() => mode.validateRequest(shapeOf("https://localhost/", { headers: { Host: "other.example" } }))).toThrow(/reserved request header cannot be set by callers: host/);
    const bound = await mode.bind(verification(PIN));
    const before = seen.length;
    await expect(bound.fetch(`${origin}/plain`, { headers: { host: "other.example" } })).rejects.toThrow(ConfigurationError);
    await expect(bound.fetch(new Request(`${origin}/plain`, { headers: { host: "other.example" } }))).rejects.toThrow(ConfigurationError);
    expect(seen.length).toBe(before);
    bound.close?.();
  });

  it("hands a redirect back as the response it is, never following it, or fails it when the request asked for that", async () => {
    const bound = await mode.bind(verification(PIN));
    const before = seen.length;
    const res = await bound.fetch(`${origin}/redirect`, { redirect: "follow" });
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe(`${origin}/plain`);
    await res.text();
    expect(seen.slice(before).map((s) => s.path)).toEqual(["/redirect"]);
    // A request that asked for an error on a redirect gets one, from either form of input.
    await expect(bound.fetch(`${origin}/redirect`, { redirect: "error" })).rejects.toBeInstanceOf(NetworkError);
    await expect(bound.fetch(new Request(`${origin}/redirect`, { redirect: "error" }))).rejects.toBeInstanceOf(NetworkError);
    expect(seen.slice(before).map((s) => s.path)).toEqual(["/redirect", "/redirect", "/redirect"]);
    bound.close?.();
  });

  it("pools a connection across requests, and retires a binding without cutting a request in flight, closing its idle connections and pooling no more", async () => {
    await until(() => open === 0);
    const idle = await mode.bind(verification(PIN));
    const before = accepted;
    expect(await (await idle.fetch(`${origin}/plain`)).text()).toBe("hello");
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(open).toBe(1);
    expect(await (await idle.fetch(`${origin}/plain`)).text()).toBe("hello");
    expect(accepted).toBe(before + 1);
    idle.retire?.();
    await until(() => open === 0);

    const busy = await mode.bind(verification(PIN));
    const res = await busy.fetch(`${origin}/sse`);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let text = decoder.decode((await reader.read()).value);
    expect(open).toBe(1);
    busy.retire?.();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value);
    }
    expect(text).toBe("data: chunk 1\n\ndata: chunk 2\n\ndata: chunk 3\n\n");
    // The connection the request used is closed once it is freed, not pooled.
    await until(() => open === 0);
    // A request sent to a retired binding still goes out, on a connection that isn't kept.
    expect(await (await busy.fetch(`${origin}/plain`)).text()).toBe("hello");
    await until(() => open === 0);
  });

  it("closes a binding ending a request still in flight on it", async () => {
    await until(() => open === 0);
    const bound = await mode.bind(verification(PIN));
    const reader = (await bound.fetch(`${origin}/sse`)).body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("data: chunk 1\n\n");
    bound.close?.();
    await expect(reader.read()).rejects.toThrow();
    await until(() => open === 0);
  });
});

describe("KeyedTransport over TLS", () => {
  function verifier(keys: () => string): Verifier {
    return { checkPinVerifiability: () => {}, verifyV3At: async () => verification(keys()) } as unknown as Verifier;
  }

  it("replays once after a key rotation, re-verifying in between, and refuses other origins", async () => {
    let verified = 0;
    const enclave = await Enclave.create({
      host: "localhost",
      pin: {},
      verifier: verifier(() => (verified++ === 0 ? OTHER : PIN)),
      fetch: async () => new Response(new Uint8Array([1])),
      sleep: async () => {},
    });
    const t = new KeyedTransport(enclave, tlsMode({ ca: cert }));
    const before = seen.length;
    const err = await t.fetch(`${origin}/plain`).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyRejectionError);
    expect(seen.length).toBe(before);
    const replayed = withReplay(t.fetch, isKeyRejection);
    expect(await (await replayed(`${origin}/plain`)).text()).toBe("hello");
    expect(verified).toBe(2);
    expect(t.current()?.tlsPublicKeyFP).toBe(PIN);
    await expect(t.fetch(`http://localhost:1/`)).rejects.toThrow(ConfigurationError);
    const state = await t.state();
    (state.bound as BoundFetch).close?.();
  });
});
