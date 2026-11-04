/**
 * The TLS transport against a local HTTPS server: the pin on every
 * connection (a matching key serves, a mismatch fails in the handshake and
 * no request reaches the server), plaintext refused, response bodies
 * streamed chunk by chunk as the server writes them, request bodies
 * streamed as they are produced, and the replay after a key rotation.
 */
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError } from "../../src/v3/errors.js";
import { Enclave } from "../../src/v3/internal/enclave.js";
import { withReplay } from "../../src/v3/internal/transport/replay.js";
import { tlsMode } from "../../src/v3/internal/transport/tls.js";
import { isKeyRejection, KeyedTransport, KeyRejectionError, PeerLacksKeyError, shapeOf, type BoundFetch } from "../../src/v3/internal/transport/transport.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, type Verification, type Verifier } from "../../../verifier/src/v3/index.js";

const cert = readFileSync(new URL("../fixtures/ws-test-cert.pem", import.meta.url));
const key = readFileSync(new URL("../fixtures/ws-test-key.pem", import.meta.url));
const PIN = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
const OTHER = "ab".repeat(32);

/** What the server saw: request paths, and when each streamed response ended. */
const seen: { path: string; method: string; bodyLength: number; headers: Record<string, string | string[] | undefined> }[] = [];
let server: Server;
let origin: string;
let sseEnded = false;

function verification(fp: string): Verification {
  return {
    cryptoMaterial: () => [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: fp }],
    cryptoMaterialData: (id: string) => (id === "tls" ? fp : undefined),
    tlsPublicKeyFP: () => fp,
    hpkePublicKey: () => undefined,
    freshnessExpiresAt: () => new Date(Date.now() + 60_000),
  } as unknown as Verification;
}

beforeAll(async () => {
  server = createServer({ key, cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
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
        default:
          res.writeHead(200, { "content-type": "text/plain", "x-two": "a", "set-cookie": ["a=1", "b=2"] });
          res.end("hello");
      }
    });
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
    await expect(mode.bind({ ...verification(PIN), tlsPublicKeyFP: () => undefined } as Verification)).rejects.toThrow(/endorses no "tls" key/);
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
    let pulled = 0;
    const chunk = new Uint8Array(64 * 1024).fill(7);
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulled === 8) {
          controller.close();
          return;
        }
        pulled++;
        controller.enqueue(chunk);
      },
    });
    const res = await bound.fetch(`${origin}/echo`, { method: "POST", body, headers: { "content-type": "application/octet-stream" } });
    expect(await res.json()).toEqual({ length: 8 * chunk.length, contentType: "application/octet-stream" });
    expect(pulled).toBe(8);
    bound.close?.();
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
});

describe("KeyedTransport over TLS", () => {
  function verifier(keys: () => string): Verifier {
    return { checkRepoVerifiability: () => {}, verifyV3At: async () => verification(keys()) } as unknown as Verifier;
  }

  it("replays once after a key rotation, re-verifying in between, and refuses other origins", async () => {
    let verified = 0;
    const enclave = await Enclave.create({
      host: "localhost",
      repo: "",
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
    expect(t.current()?.tlsPublicKeyFP()).toBe(PIN);
    await expect(t.fetch(`http://localhost:1/`)).rejects.toThrow(ConfigurationError);
    const state = await t.state();
    (state.bound as BoundFetch).close?.();
  });
});
