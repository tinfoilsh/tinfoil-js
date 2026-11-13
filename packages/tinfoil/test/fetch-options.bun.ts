/**
 * The TLS transport under Bun, with the Bun-only fetch options that a caller
 * can pass through openai's `fetchOptions` (`unix` and `proxy`). Each test
 * asserts that the pin still holds, so a failure here means that the option
 * bypasses it. Each test also logs what it observed.
 * Run with: bun test test/fetch-options.bun.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, connect, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tlsMode } from "../src/internal/transport/tls.js";
import { PeerLacksKeyError } from "../src/internal/transport/transport.js";
import type { Verification } from "@tinfoilsh/verifier";

const cert = readFileSync(new URL("./fixtures/ws-test-cert.pem", import.meta.url), "utf8");
const key = readFileSync(new URL("./fixtures/ws-test-key.pem", import.meta.url), "utf8");
const PIN = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
const WRONG_PIN = "ab".repeat(32);
const SECRET = "sk-fetch-options-secret";
const TIMEOUT_MS = 5_000;

function verification(fp: string): Verification {
  return {
    cryptoMaterial: [{ id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: fp }],
    tlsPublicKeyFP: fp,
    hpkePublicKey: undefined,
    freshnessExpiresAt: new Date(Date.now() + 60_000),
  } as unknown as Verification;
}

/** The request init as openai builds it, with the caller's `fetchOptions` spread in. */
function init(extra: Record<string, unknown>): RequestInit {
  return {
    method: "POST",
    headers: { authorization: `Bearer ${SECRET}`, "content-type": "application/json" },
    body: JSON.stringify({ model: "m", messages: [] }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
    ...extra,
  } as RequestInit;
}

function describeError(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  const cause = err.cause instanceof Error ? ` (cause: ${err.cause.name}: ${err.cause.message})` : "";
  return `${err.constructor.name}: ${err.message}${cause}`;
}

/** Runs the fetch, returning what happened instead of throwing. */
async function attempt(run: () => Promise<Response>): Promise<{ ok: true; status: number; body: string } | { ok: false; error: unknown }> {
  try {
    const res = await run();
    return { ok: true, status: res.status, body: await res.text() };
  } catch (error) {
    return { ok: false, error };
  }
}

function outcome(result: Awaited<ReturnType<typeof attempt>>): string {
  return result.ok ? `succeeded with status ${result.status}, body ${JSON.stringify(result.body)}` : `failed with ${describeError(result.error)}`;
}

/** A printable view of raw bytes: the first byte in hex, then the text with control bytes escaped. */
function preview(bytes: Buffer): string {
  if (bytes.length === 0) return "<no bytes>";
  const text = bytes.subarray(0, 48).toString("latin1").replace(/[^\x20-\x7e]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);
  return `${bytes.length} bytes, first byte 0x${bytes[0]!.toString(16).padStart(2, "0")}: ${text}`;
}

function listen(server: Server, target: string | number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    if (typeof target === "string") server.listen(target, () => resolve());
    else server.listen(target, "127.0.0.1", () => resolve());
  });
}

let dir: string;
let tlsServer: ReturnType<typeof Bun.serve>;
let tlsRequests = 0;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "tf-fo-"));
  tlsServer = Bun.serve({
    hostname: "localhost",
    port: 0,
    tls: { key, cert },
    fetch() {
      tlsRequests++;
      return new Response("hello");
    },
  });
});

afterAll(() => {
  tlsServer.stop(true);
  rmSync(dir, { recursive: true, force: true });
});

describe("tlsMode under Bun with caller fetch options", () => {
  const mode = tlsMode({ ca: cert });
  // Nothing listens on port 1, so a request that ignores `unix` fails to connect.
  const unixURL = "https://localhost:1/v1/chat/completions";

  it("unix: does not send the request in the clear to a plaintext server on the socket", async () => {
    const socketPath = join(dir, "plain.sock");
    const received: Buffer[] = [];
    let connections = 0;
    const server = createServer((socket: Socket) => {
      connections++;
      socket.on("error", () => {});
      socket.on("data", (chunk: Buffer) => {
        received.push(chunk);
        const all = Buffer.concat(received);
        if (all[0] === 0x16) {
          socket.destroy(); // A TLS ClientHello: this server can't speak TLS.
        } else if (all.includes("\r\n\r\n")) {
          socket.end("HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello");
        }
      });
    });
    await listen(server, socketPath);
    try {
      const bound = await mode.bind(verification(PIN));
      const result = await attempt(() => bound.fetch(unixURL, init({ unix: socketPath })));
      const bytes = Buffer.concat(received);
      console.log(`[unix -> plaintext server] fetch ${outcome(result)}; connections: ${connections}; server received ${preview(bytes)}`);
      expect(result.ok).toBe(false);
      expect(bytes.includes(SECRET)).toBe(false);
      expect(bytes.toString("latin1").toLowerCase().includes("authorization")).toBe(false);
      expect(/^[A-Z]+ \S+ HTTP\/1\.[01]\r\n/.test(bytes.toString("latin1"))).toBe(false);
    } finally {
      server.close();
    }
  }, 15_000);

  it("unix: fails closed against a TLS server on the socket whose key is not the pinned one", async () => {
    const socketPath = join(dir, "tls-wrong.sock");
    let handled = 0;
    const server = Bun.serve({
      unix: socketPath,
      tls: { key, cert },
      fetch() {
        handled++;
        return new Response("hello");
      },
    });
    try {
      const bound = await mode.bind(verification(WRONG_PIN));
      const result = await attempt(() => bound.fetch(unixURL, init({ unix: socketPath })));
      console.log(`[unix -> TLS server, wrong key] fetch ${outcome(result)}; handler saw ${handled} request(s)`);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBeInstanceOf(PeerLacksKeyError);
      expect(handled).toBe(0);
    } finally {
      server.stop(true);
    }
  }, 15_000);

  it("unix: against a TLS server on the socket with the pinned key (observation only)", async () => {
    const socketPath = join(dir, "tls-pinned.sock");
    let handled = 0;
    const server = Bun.serve({
      unix: socketPath,
      tls: { key, cert },
      fetch() {
        handled++;
        return new Response("hello");
      },
    });
    try {
      const bound = await mode.bind(verification(PIN));
      const result = await attempt(() => bound.fetch(unixURL, init({ unix: socketPath })));
      console.log(`[unix -> TLS server, pinned key] fetch ${outcome(result)}; handler saw ${handled} request(s)`);
      // Either outcome is safe here: it only tells us whether `unix` keeps TLS.
      if (result.ok) expect(handled).toBe(1);
    } finally {
      server.stop(true);
    }
  }, 15_000);

  describe("proxy", () => {
    let proxy: Server;
    let proxyURL: string;
    const requestLines: string[] = [];
    const clientBytes: Buffer[] = [];

    beforeAll(async () => {
      proxy = createServer((client: Socket) => {
        client.on("error", () => {});
        let head = Buffer.alloc(0);
        const onData = (chunk: Buffer): void => {
          clientBytes.push(chunk);
          head = Buffer.concat([head, chunk]);
          const end = head.indexOf("\r\n\r\n");
          if (end === -1) return;
          client.off("data", onData);
          const line = head.subarray(0, head.indexOf("\r\n")).toString("latin1");
          requestLines.push(line);
          const match = /^CONNECT ([^:\s]+):(\d+) HTTP\/1\.[01]$/.exec(line);
          if (match === null) {
            client.end("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            return;
          }
          const upstream = connect(Number(match[2]), match[1]!, () => {
            client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            const rest = head.subarray(end + 4);
            if (rest.length > 0) upstream.write(rest);
            client.on("data", (more: Buffer) => clientBytes.push(more));
            client.pipe(upstream);
            upstream.pipe(client);
          });
          upstream.on("error", () => client.destroy());
          client.on("close", () => upstream.destroy());
        };
        client.on("data", onData);
      });
      await listen(proxy, 0);
      const address = proxy.address();
      if (address === null || typeof address === "string") throw new Error("proxy has no port");
      proxyURL = `http://127.0.0.1:${address.port}`;
    });

    afterAll(() => {
      proxy.close();
    });

    function reset(): void {
      requestLines.length = 0;
      clientBytes.length = 0;
    }

    function seen(): string {
      const bytes = Buffer.concat(clientBytes);
      return `proxy request lines: ${JSON.stringify(requestLines)}; secret visible to proxy: ${bytes.includes(SECRET)}; tunnelled bytes after the CONNECT head: ${preview(tunnelled(bytes))}`;
    }

    function tunnelled(bytes: Buffer): Buffer {
      const end = bytes.indexOf("\r\n\r\n");
      return end === -1 ? Buffer.alloc(0) : bytes.subarray(end + 4);
    }

    it("fails closed through a CONNECT proxy to a server whose key is not the pinned one", async () => {
      reset();
      const before = tlsRequests;
      const bound = await mode.bind(verification(WRONG_PIN));
      const result = await attempt(() => bound.fetch(`https://localhost:${tlsServer.port}/v1/chat/completions`, init({ proxy: proxyURL })));
      console.log(`[proxy -> TLS server, wrong key] fetch ${outcome(result)}; handler saw ${tlsRequests - before} request(s); ${seen()}`);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBeInstanceOf(PeerLacksKeyError);
      expect(tlsRequests).toBe(before);
      expect(Buffer.concat(clientBytes).includes(SECRET)).toBe(false);
    }, 15_000);

    it("through a CONNECT proxy to the pinned server (observation only)", async () => {
      reset();
      const before = tlsRequests;
      const bound = await mode.bind(verification(PIN));
      const result = await attempt(() => bound.fetch(`https://localhost:${tlsServer.port}/v1/chat/completions`, init({ proxy: proxyURL })));
      console.log(`[proxy -> TLS server, pinned key] fetch ${outcome(result)}; handler saw ${tlsRequests - before} request(s); ${seen()}`);
      // Either outcome is safe; the request must never cross the proxy in the clear.
      expect(Buffer.concat(clientBytes).includes(SECRET)).toBe(false);
    }, 15_000);
  });
});
