import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "https";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { X509Certificate, createHash } from "crypto";
import { WebSocketServer, type WebSocket } from "ws";
import { createPinnedWebSocket } from "../src/pinned-ws.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cert = readFileSync(resolve(__dirname, "fixtures/ws-test-cert.pem"));
const key = readFileSync(resolve(__dirname, "fixtures/ws-test-key.pem"));

const x509 = new X509Certificate(cert);
const correctFingerprint = createHash("sha256")
  .update(x509.publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
const wrongFingerprint = "0".repeat(64);

let server: Server;
let wss: WebSocketServer;
let port: number;

function waitForOutcome(socket: WebSocket): Promise<"open" | Error> {
  return new Promise((resolve) => {
    socket.on("open", () => resolve("open"));
    socket.on("error", (err) => resolve(err));
  });
}

beforeAll(async () => {
  server = createServer({ cert, key });
  wss = new WebSocketServer({ server });
  wss.on("connection", (socket) => {
    socket.on("message", (data) => socket.send(data));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address === "object" && address) {
    port = address.port;
  }
});

afterAll(async () => {
  wss.close();
  await new Promise((resolve) => server.close(resolve));
});

describe("createPinnedWebSocket", () => {
  it("connects and exchanges messages when the fingerprint matches", async () => {
    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      correctFingerprint,
      { wsOptions: { ca: [cert] } },
    );
    const outcome = await waitForOutcome(socket);
    expect(outcome).toBe("open");

    const echoed = await new Promise<string>((resolve) => {
      socket.on("message", (data) => resolve(data.toString()));
      socket.send("ping");
    });
    expect(echoed).toBe("ping");
    socket.close();
  });

  it("rejects the connection when the fingerprint does not match", async () => {
    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      wrongFingerprint,
      { wsOptions: { ca: [cert] } },
    );
    const outcome = await waitForOutcome(socket);
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toContain("TLS pinning failed");
  });

  it("does not allow wsOptions to disable pinning", async () => {
    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      wrongFingerprint,
      {
        wsOptions: {
          ca: [cert],
          rejectUnauthorized: false,
          checkServerIdentity: () => undefined,
        } as any,
      },
    );
    const outcome = await waitForOutcome(socket);
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toContain("TLS pinning failed");
  });

  it("rejects ws:// URLs", async () => {
    await expect(
      createPinnedWebSocket(`ws://localhost:${port}/test`, correctFingerprint),
    ).rejects.toThrow("Insecure connection rejected");
  });
});
