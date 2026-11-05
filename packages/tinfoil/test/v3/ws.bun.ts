/**
 * Pinned WebSockets under Bun, against a local TLS WebSocket server: a
 * matching key connects and echoes, a mismatch fails closed without the
 * server seeing a connection, plaintext is refused.
 * Run with: bun test test/v3/ws.bun.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { createEnclaveHTTPClient, type EnclaveHTTPClient } from "../../src/v3/enclave-client.js";
import { AttestationError, ConfigurationError } from "../../src/v3/errors.js";
import type { Fetch, PinnedWebSocket } from "../../src/v3/options.js";
import { createWebSocket } from "../../src/v3/websocket.js";
import type { Verification, Verifier } from "@tinfoilsh/verifier";

const cert = readFileSync(new URL("../fixtures/ws-test-cert.pem", import.meta.url), "utf8");
const key = readFileSync(new URL("../fixtures/ws-test-key.pem", import.meta.url), "utf8");
const PIN = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");

function verifier(pin: string): Verifier {
  return {
    checkRepoVerifiability: () => {},
    verifyV3At: async () =>
      ({
        cryptoMaterial: () => [{ id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: pin }],
        tlsPublicKeyFP: () => pin,
        hpkePublicKey: () => undefined,
        freshnessExpiresAt: () => new Date(Date.now() + 60_000),
      }) as unknown as Verification,
  } as unknown as Verifier;
}

const documentFetch: Fetch = async () => new Response(new Uint8Array([1]));

let server: ReturnType<typeof Bun.serve>;
let host: string;
let connections = 0;

beforeAll(() => {
  server = Bun.serve({
    hostname: "localhost",
    port: 0,
    tls: { key, cert },
    fetch(request, srv) {
      return srv.upgrade(request, { data: undefined }) ? undefined : new Response("not a websocket", { status: 426 });
    },
    websocket: {
      open() {
        connections++;
      },
      message(ws, message) {
        ws.send(`echo:${String(message)}`);
      },
    },
  });
  host = `localhost:${server.port}`;
});

afterAll(() => {
  server.stop(true);
});

function client(pin: string): Promise<EnclaveHTTPClient> {
  return createEnclaveHTTPClient(host, "tinfoilsh/repo", { verifier: verifier(pin), transportMode: "tls" }, { documentFetch, tls: { ca: cert } });
}

function opened(socket: PinnedWebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("error", (event) => reject(event.error ?? new Error(event.message ?? "error")), { once: true });
    socket.addEventListener("close", (event) => reject(new Error(`closed: ${event.code} ${event.reason}`)), { once: true });
  });
}

describe("createWebSocket under Bun", () => {
  it("connects when the certificate carries the pinned key and carries messages both ways", async () => {
    const socket = await createWebSocket(await client(PIN), "/v1/realtime");
    await opened(socket);
    const reply = new Promise<string>((resolve) => socket.addEventListener("message", (event) => resolve(String(event.data)), { once: true }));
    socket.send("ping");
    expect(await reply).toBe("echo:ping");
    socket.close();
  });

  it("fails closed when the certificate carries another key, without the server seeing a connection", async () => {
    const before = connections;
    const socket = await createWebSocket(await client("ab".repeat(32)), "/never");
    const err = await opened(socket).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as Error).message).toMatch(/does not match the attested key/);
    expect(connections).toBe(before);
  });

  it("refuses plaintext", async () => {
    await expect(createWebSocket(await client(PIN), `ws://${host}/x`)).rejects.toBeInstanceOf(ConfigurationError);
  });
});
