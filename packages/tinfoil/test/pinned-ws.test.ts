import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import {
  Agent as HttpsAgent,
  createServer as createHttpsServer,
  type Server,
} from "https";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { X509Certificate, createHash } from "crypto";
import { WebSocketServer, type WebSocket } from "ws";
import { createPinnedWebSocket, pinnedWsClientOptions } from "../src/pinned-ws.js";

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
let plaintextWss: WebSocketServer;
let port: number;
let plaintextPort: number;
let plaintextConnections = 0;

function waitForOutcome(socket: WebSocket): Promise<"open" | Error> {
  return new Promise((resolve) => {
    socket.on("open", () => resolve("open"));
    socket.on("error", (err) => resolve(err));
  });
}

beforeAll(async () => {
  plaintextWss = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  plaintextWss.on("connection", (socket) => {
    plaintextConnections += 1;
    socket.close();
  });
  await new Promise<void>((resolve) => plaintextWss.on("listening", resolve));
  const plaintextAddress = plaintextWss.address();
  if (typeof plaintextAddress === "object" && plaintextAddress) {
    plaintextPort = plaintextAddress.port;
  }

  server = createHttpsServer({ cert, key }, (_req, res) => {
    res.writeHead(404);
    res.end();
  });
  wss = new WebSocketServer({ noServer: true });
  wss.on("connection", (socket) => {
    socket.on("message", (data) => socket.send(data));
  });
  server.on("upgrade", (req, socket, head) => {
    if (req.url === "/redirect-plaintext") {
      socket.write(
        "HTTP/1.1 302 Found\r\n" +
          `Location: ws://127.0.0.1:${plaintextPort}/test\r\n` +
          "Connection: close\r\n\r\n",
      );
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address === "object" && address) {
    port = address.port;
  }
});

afterAll(async () => {
  wss.close();
  plaintextWss.close();
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

  it("strips createConnection so wsOptions cannot bypass pinning", async () => {
    const createConnection = vi.fn();
    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      wrongFingerprint,
      { wsOptions: { ca: [cert], createConnection } as any },
    );
    const outcome = await waitForOutcome(socket);
    expect(createConnection).not.toHaveBeenCalled();
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toContain("TLS pinning failed");
  });

  it("strips custom agents so wsOptions cannot bypass pinning", async () => {
    const agent = new HttpsAgent();
    const createConnection = vi.spyOn(agent, "createConnection");
    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      wrongFingerprint,
      { wsOptions: { ca: [cert], agent } as any },
    );
    const outcome = await waitForOutcome(socket);
    expect(createConnection).not.toHaveBeenCalled();
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toContain("TLS pinning failed");
    agent.destroy();
  });

  it("strips TLS sessions so resumption cannot bypass pinning", async () => {
    const firstSocket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      correctFingerprint,
      { wsOptions: { ca: [cert] } },
    );
    expect(await waitForOutcome(firstSocket)).toBe("open");
    const session = (firstSocket as any)._socket?.getSession?.();
    expect(session?.length).toBeGreaterThan(0);
    firstSocket.close();

    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      wrongFingerprint,
      { wsOptions: { ca: [cert], session } as any },
    );
    const outcome = await waitForOutcome(socket);
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toContain("TLS pinning failed");
  });

  it("strips servername so hostname validation uses the URL host", async () => {
    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/test`,
      correctFingerprint,
      { wsOptions: { ca: [cert], servername: "example.com" } as any },
    );
    const outcome = await waitForOutcome(socket);
    expect(outcome).toBe("open");
    socket.close();
  });

  it("does not follow redirects outside the pinned TLS connection", async () => {
    plaintextConnections = 0;
    const socket = await createPinnedWebSocket(
      `wss://localhost:${port}/redirect-plaintext`,
      correctFingerprint,
      { wsOptions: { ca: [cert], followRedirects: true } },
    );
    const outcome = await waitForOutcome(socket);
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toContain("Unexpected server response: 302");
    expect(plaintextConnections).toBe(0);
  });

  it("rejects ws:// URLs", async () => {
    await expect(
      createPinnedWebSocket(`ws://localhost:${port}/test`, correctFingerprint),
    ).rejects.toThrow("Insecure connection rejected");
  });

  it("returns pinned options that clear unsafe options when spread last", async () => {
    const pinnedOptions = await pinnedWsClientOptions(correctFingerprint);
    const agent = new HttpsAgent();
    const merged = {
      createConnection: vi.fn(),
      agent,
      followRedirects: true,
      session: Buffer.from("test"),
      socket: {},
      servername: "example.com",
      pskCallback: vi.fn(),
      ...pinnedOptions,
    };
    expect(merged.createConnection).toBeUndefined();
    expect(merged.agent).toBeUndefined();
    expect(merged.followRedirects).toBe(false);
    expect(merged.session).toBeUndefined();
    expect(merged.socket).toBeUndefined();
    expect(merged.servername).toBeUndefined();
    expect(merged.pskCallback).toBeUndefined();
    expect(merged.rejectUnauthorized).toBe(true);
    agent.destroy();
  });
});
