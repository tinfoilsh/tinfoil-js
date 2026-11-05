/**
 * Pinned WebSockets against a local TLS WebSocket server: a matching key
 * connects and carries messages both ways with the handshake's headers and
 * subprotocol, a mismatch fails in the handshake with no connection reaching
 * the server and makes the client verify again, plaintext and other hosts
 * are refused before any I/O, and the `ws` settings a library needs pin its
 * own connection the same way.
 */
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { Identity } from "ehbp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WebSocket as WsWebSocket, WebSocketServer } from "ws";
import { createEnclaveHTTPClient, type EnclaveHTTPClient } from "../src/enclave-client.js";
import { AttestationError, ConfigurationError } from "../src/errors.js";
import { PeerLacksKeyError } from "../src/internal/transport/transport.js";
import { isCertificateError } from "../src/internal/transport/pin-errors.js";
import { allowedWsOptions } from "../src/internal/transport/ws.js";
import { checkWebSocketCapability, webSocketURL } from "../src/internal/websocket.js";
import type { Fetch, PinnedWebSocket } from "../src/options.js";
import { createWebSocket, pinnedWebSocketOptions } from "../src/websocket.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verification, type Verifier } from "../../verifier/src/index.js";
import { TEST_CERT, TEST_KEY, TEST_PIN } from "./helpers/tls-server.js";

const OTHER_PIN = "ab".repeat(32);

interface Connection {
  readonly path: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly protocol: string;
}

let server: Server;
let wss: WebSocketServer;
let host: string;
const connections: Connection[] = [];

function verifier(pin: () => string): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo.includes(" ")) throw new UsageError(`bad repo ${repo}`);
    },
    verifyV3At: async () =>
      ({
        cryptoMaterial: () => [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: pin() }],
        tlsPublicKeyFP: () => pin(),
        hpkePublicKey: () => undefined,
        codeDigest: () => "11".repeat(32),
        freshnessExpiresAt: () => new Date(Date.now() + 60_000),
      }) as unknown as Verification,
  } as unknown as Verifier;
}

function documents(): { fetch: Fetch; calls: number } {
  const docs = {
    calls: 0,
    fetch: (async () => {
      docs.calls++;
      return new Response(new Uint8Array([1]));
    }) as Fetch,
  };
  return docs;
}

async function client(pin: () => string, docs = documents()): Promise<EnclaveHTTPClient> {
  return createEnclaveHTTPClient(host, "tinfoilsh/repo", { verifier: verifier(pin), transportMode: "tls" }, { documentFetch: docs.fetch, tls: { ca: TEST_CERT } });
}

/** Resolves on the socket's open event, or rejects with its error. */
function opened(socket: PinnedWebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("error", (event) => reject(event.error ?? new Error(event.message)), { once: true });
  });
}

/** The next message the socket receives, as text. */
function nextMessage(socket: PinnedWebSocket): Promise<string> {
  return new Promise((resolve) => socket.addEventListener("message", (event) => resolve(String(event.data)), { once: true }));
}

beforeAll(async () => {
  server = createServer({ key: TEST_KEY, cert: TEST_CERT });
  wss = new WebSocketServer({ server, handleProtocols: (protocols) => [...protocols][0] ?? false });
  wss.on("connection", (socket, request) => {
    connections.push({ path: request.url ?? "", headers: request.headers, protocol: socket.protocol });
    socket.on("message", (data) => socket.send(`echo:${String(data)}`));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  host = `localhost:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  for (const socket of wss.clients) socket.terminate();
  await new Promise<void>((resolve) => wss.close(() => resolve()));
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("webSocketURL", () => {
  it("resolves a path against the enclave as wss and accepts a URL on the enclave's origin", () => {
    expect(webSocketURL("enclave.example", "/v1/realtime?model=m").toString()).toBe("wss://enclave.example/v1/realtime?model=m");
    expect(webSocketURL("enclave.example:8443", "/x").toString()).toBe("wss://enclave.example:8443/x");
    expect(webSocketURL("enclave.example", "https://enclave.example/x").toString()).toBe("wss://enclave.example/x");
    expect(webSocketURL("enclave.example", "wss://enclave.example:443/x").toString()).toBe("wss://enclave.example/x");
  });

  it("refuses plaintext and any other host before any I/O", () => {
    expect(() => webSocketURL("enclave.example", "ws://enclave.example/x")).toThrow(/requires wss:\/\//);
    expect(() => webSocketURL("enclave.example", "http://enclave.example/x")).toThrow(/requires wss:\/\//);
    expect(() => webSocketURL("enclave.example", "wss://other.example/x")).toThrow(/bound to enclave "enclave.example"/);
    expect(() => webSocketURL("enclave.example", "wss://enclave.example:8443/x")).toThrow(ConfigurationError);
    expect(() => webSocketURL("enclave.example", "https://")).toThrow(ConfigurationError);
  });

  it("is available only on a runtime that identifies itself as a server", () => {
    expect(() => checkWebSocketCapability({ process: { versions: { node: "22.0.0" } } })).not.toThrow();
    expect(() => checkWebSocketCapability({ Bun: {} })).not.toThrow();
    expect(() => checkWebSocketCapability({ self: {} } as never)).toThrow(/browsers don't expose/);
  });

  it("drops the ws settings that would change the peer or its certificate check", () => {
    expect(allowedWsOptions({ agent: 1, createConnection: 2, checkServerIdentity: 3, rejectUnauthorized: false, ca: "x", headers: {}, perMessageDeflate: false, maxPayload: 7 })).toEqual({
      perMessageDeflate: false,
      maxPayload: 7,
    });
    expect(allowedWsOptions(undefined)).toEqual({});
  });

  it("recognises the pin's rejection and the runtime's certificate errors, and nothing else", () => {
    expect(isCertificateError(new PeerLacksKeyError("x"))).toBe(true);
    expect(isCertificateError(new AttestationError("x"))).toBe(false);
    expect(isCertificateError(Object.assign(new Error("x"), { code: "CERT_HAS_EXPIRED" }))).toBe(true);
    expect(isCertificateError(Object.assign(new Error("x"), { code: "ERR_TLS_CERT_ALTNAME_INVALID" }))).toBe(true);
    expect(isCertificateError(Object.assign(new Error("x"), { code: "ECONNREFUSED" }))).toBe(false);
    expect(isCertificateError(undefined)).toBe(false);
  });
});

describe("createWebSocket", () => {
  it("connects over a connection carrying the pinned key, with the handshake's headers and subprotocol, and carries messages both ways", async () => {
    const c = await client(() => TEST_PIN);
    const socket = await createWebSocket(c, "/v1/realtime?model=m", { headers: { Authorization: "Bearer k" }, protocols: ["realtime", "other"] });
    await opened(socket);
    expect(socket.readyState).toBe(WsWebSocket.OPEN);
    expect(socket.protocol).toBe("realtime");
    const last = connections[connections.length - 1]!;
    expect(last.path).toBe("/v1/realtime?model=m");
    expect(last.headers.authorization).toBe("Bearer k");
    expect(last.headers["sec-websocket-protocol"]).toBe("realtime,other");
    const reply = nextMessage(socket);
    socket.send("ping");
    expect(await reply).toBe("echo:ping");
    socket.close();
  });

  it("fails in the handshake when the certificate carries another key, reaches the server with nothing, and verifies again afterwards", async () => {
    const docs = documents();
    const c = await client(() => OTHER_PIN, docs);
    expect(docs.calls).toBe(1);
    const before = connections.length;
    const socket = await createWebSocket(c, "/v1/realtime");
    const err = await opened(socket).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as Error).message).toMatch(/does not match the attested key/);
    expect(connections.length).toBe(before);
    // The pin failure retired the verification the socket was opened under.
    await c.ensureVerified();
    expect(docs.calls).toBe(2);
  });

  it("fails closed when the normal certificate check fails, and verifies again afterwards", async () => {
    const docs = documents();
    const c = await createEnclaveHTTPClient(host, "tinfoilsh/repo", { verifier: verifier(() => TEST_PIN), transportMode: "tls" }, { documentFetch: docs.fetch });
    const before = connections.length;
    const socket = await createWebSocket(c, "/x");
    const err = (await opened(socket).catch((e: unknown) => e)) as { code?: string };
    expect(err.code).toMatch(/SELF_SIGNED|UNABLE_TO|DEPTH_ZERO|CERT_/);
    expect(connections.length).toBe(before);
    await c.ensureVerified();
    expect(docs.calls).toBe(2);
  });

  it("refuses plaintext, other hosts and a client it didn't create, before any I/O", async () => {
    const docs = documents();
    const c = await client(() => TEST_PIN, docs);
    const before = connections.length;
    await expect(createWebSocket(c, `ws://${host}/x`)).rejects.toBeInstanceOf(ConfigurationError);
    await expect(createWebSocket(c, "wss://other.example/x")).rejects.toThrow(/bound to enclave/);
    await expect(createWebSocket({} as EnclaveHTTPClient, "/x")).rejects.toThrow(/not created by its factory/);
    expect(connections.length).toBe(before);
    expect(docs.calls).toBe(1);
  });

  it("works in either transport mode, always directly to the enclave", async () => {
    const hpke = await (await Identity.generate()).getPublicKeyHex();
    const sealing = {
      ...verifier(() => TEST_PIN),
      verifyV3At: async () =>
        ({
          cryptoMaterial: () => [
            { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: TEST_PIN },
            { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke },
          ],
          tlsPublicKeyFP: () => TEST_PIN,
          hpkePublicKey: () => hpke,
          codeDigest: () => "11".repeat(32),
          freshnessExpiresAt: () => new Date(Date.now() + 60_000),
        }) as unknown as Verification,
    } as unknown as Verifier;
    const c = await createEnclaveHTTPClient(host, "tinfoilsh/repo", { verifier: sealing, transportMode: "ehbp" }, { documentFetch: documents().fetch, tls: { ca: TEST_CERT } });
    const socket = await createWebSocket(c, "/x");
    await opened(socket);
    socket.close();
  });
});

describe("pinnedWebSocketOptions", () => {
  it("pins a ws client built by a library, with the normal certificate check kept on", async () => {
    const options = await pinnedWebSocketOptions(await client(() => TEST_PIN));
    expect(options.rejectUnauthorized).toBe(true);
    expect(options.followRedirects).toBe(false);
    expect(typeof options.checkServerIdentity).toBe("function");
    const socket = new WsWebSocket(`wss://${host}/lib`, options) as unknown as PinnedWebSocket;
    await opened(socket);
    expect(connections[connections.length - 1]!.path).toBe("/lib");
    socket.close();

  });

  it("fails a library's handshake when the certificate carries another key, reaches the server with nothing, and verifies again afterwards", async () => {
    const docs = documents();
    const c = await client(() => OTHER_PIN, docs);
    expect(docs.calls).toBe(1);
    const before = connections.length;
    const mismatched = new WsWebSocket(`wss://${host}/lib`, await pinnedWebSocketOptions(c)) as unknown as PinnedWebSocket;
    const err = await opened(mismatched).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as Error).message).toMatch(/does not match the attested key/);
    expect(connections.length).toBe(before);
    // The pin failure retired the verification the settings were pinned to.
    expect(docs.calls).toBe(1);
    await pinnedWebSocketOptions(c);
    expect(docs.calls).toBe(2);
  });
});
