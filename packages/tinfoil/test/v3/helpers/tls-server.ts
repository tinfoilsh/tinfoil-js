/**
 * A local HTTPS server for tests, on the package's test certificate
 * (CN localhost, SAN localhost and 127.0.0.1). Routes decide status,
 * headers and body; a body given as an async iterable is written chunk by
 * chunk as it is produced.
 */
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";

export const TEST_CERT = readFileSync(new URL("../../fixtures/ws-test-cert.pem", import.meta.url));
export const TEST_KEY = readFileSync(new URL("../../fixtures/ws-test-key.pem", import.meta.url));
/** The SPKI SHA-256 fingerprint of the test certificate's key: the pin a verification must carry to reach the server. */
export const TEST_PIN = createHash("sha256").update(new X509Certificate(TEST_CERT).publicKey.export({ type: "spki", format: "der" })).digest("hex");

export interface Seen {
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: Uint8Array;
}

export interface Reply {
  readonly status?: number;
  readonly headers?: Record<string, string | string[]>;
  readonly body?: string | Uint8Array | AsyncIterable<Uint8Array>;
}

export interface TlsServer {
  /** `https://localhost:<port>` */
  readonly origin: string;
  /** `localhost:<port>` */
  readonly host: string;
  readonly seen: Seen[];
  close(): Promise<void>;
}

export async function startTlsServer(route: (seen: Seen) => Reply | Promise<Reply>): Promise<TlsServer> {
  const seen: Seen[] = [];
  const server: Server = createServer({ key: TEST_KEY, cert: TEST_CERT }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      void (async () => {
        const request: Seen = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body: new Uint8Array(Buffer.concat(chunks)) };
        seen.push(request);
        const reply = await route(request);
        res.writeHead(reply.status ?? 200, reply.headers);
        const body = reply.body;
        if (body === undefined) {
          res.end();
        } else if (typeof body === "string" || body instanceof Uint8Array) {
          res.end(Buffer.from(body));
        } else {
          for await (const chunk of body) res.write(Buffer.from(chunk));
          res.end();
        }
      })().catch((err: unknown) => {
        // Once headers are out, the client already has a status; cut the connection instead.
        if (res.headersSent) {
          res.destroy(err instanceof Error ? err : new Error(String(err)));
          return;
        }
        res.writeHead(500, { "content-type": "text/plain" });
        res.end(String(err));
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `https://localhost:${port}`,
    host: `localhost:${port}`,
    seen,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** Yields `chunks` one by one with `delayMs` between them, and runs `onEnd` after the last. */
export async function* paced(chunks: string[], delayMs: number, onEnd?: () => void): AsyncGenerator<Uint8Array> {
  const encoder = new TextEncoder();
  for (const [i, chunk] of chunks.entries()) {
    if (i > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
    yield encoder.encode(chunk);
  }
  onEnd?.();
}
