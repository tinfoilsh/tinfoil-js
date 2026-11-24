/**
 * Pinned WebSockets against a local TLS WebSocket server: a matching key
 * connects and carries messages both ways with the handshake's headers and
 * subprotocol, a mismatch fails in the handshake with no connection reaching
 * the server and makes the client verify again, plaintext and other hosts
 * are refused before any I/O, and the `ws` settings a library needs pin its
 * own connection the same way. The openai package's own WebSocket classes
 * are refused a Tinfoil OpenAI client before they open anything.
 */
import { getEventListeners } from "node:events";
import { createServer, type Server } from "node:https";
import { createServer as createTCPServer, type AddressInfo, type Server as TCPServer } from "node:net";
import { Identity } from "ehbp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import OpenAI from "openai";
import { OpenAIRealtimeWebSocket as BetaOpenAIRealtimeWebSocket } from "openai/beta/realtime/websocket";
import { OpenAIRealtimeWS as BetaOpenAIRealtimeWS } from "openai/beta/realtime/ws";
import { OpenAIRealtimeTranslationWS } from "openai/realtime/translations/ws";
import { OpenAIRealtimeWebSocket } from "openai/realtime/websocket";
import { OpenAIRealtimeWS } from "openai/realtime/ws";
import { ResponsesWS as BetaResponsesWS } from "openai/resources/beta/responses/ws";
import { ForksWS } from "openai/resources/live/forks/ws";
import { SidebandWS } from "openai/resources/live/sideband/ws";
import { LiveWS } from "openai/resources/live/ws";
import { ResponsesWS } from "openai/resources/responses/ws";
import { type ClientOptions as WsClientOptions, WebSocket as WsWebSocket, WebSocketServer } from "ws";
import { createEnclaveHTTPClient, type EnclaveHTTPClient } from "../src/enclave-client.js";
import { AttestationError, ConfigurationError } from "../src/errors.js";
import { PeerLacksKeyError } from "../src/internal/transport/transport.js";
import { isCertificateError } from "../src/internal/transport/pin-errors.js";
import { checkWebSocketCapability, webSocketURL } from "../src/internal/websocket.js";
import { checkedWsOptions } from "../src/internal/ws-options.js";
import { OPENAI_WEBSOCKETS_REFUSED, type OpenAIClient, type OpenAIClientOptions } from "../src/openai-client.js";
import type { Fetch, PinnedWebSocket } from "../src/options.js";
import { createRealtimeWebSocket } from "../src/realtime.js";
import { createWebSocket, pinnedWebSocketOptions } from "../src/websocket.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verifier } from "../../verifier/src/index.js";
import { TEST_CERT, TEST_KEY, TEST_PIN } from "./helpers/tls-server.js";
import { openAIOver } from "./helpers/openai.js";
import { verifiedReport } from "./helpers/report.js";

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
    checkPinVerifiability: ({ repo = "" }: { repo?: string }) => {
      if (repo.includes(" ")) throw new UsageError(`bad repo ${repo}`);
    },
    verifyV3At: async () =>
      verifiedReport({
        cryptoMaterial: [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: pin() }],
        tlsPublicKeyFP: pin(),
        hpkePublicKey: undefined,
        codeDigest: "11".repeat(32),
        freshnessExpiresAt: new Date(Date.now() + 60_000),
      }),
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
  return createEnclaveHTTPClient(host, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" } }, { verifier: verifier(pin), documentFetch: docs.fetch, tls: { ca: TEST_CERT } });
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

/** An enclave OpenAI client in TLS mode, verified against `pin`, with documents from `docs`. */
async function openAIClient(openaiOptions: OpenAIClientOptions, pin: () => string = () => TEST_PIN, docs = documents()): Promise<OpenAIClient<EnclaveHTTPClient>> {
  return openAIOver(client(pin, docs), openaiOptions);
}

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

  it("refuses each ws setting that would change the peer or its certificate check, naming it", () => {
    for (const key of ["agent", "createConnection", "followRedirects", "session", "socket", "servername", "pskCallback", "checkServerIdentity", "rejectUnauthorized", "ca"]) {
      for (const caller of ["createWebSocket", "createRealtimeWebSocket"] as const) {
        // A falsy value is still a setting: `rejectUnauthorized: false` would turn the check off.
        expect(() => checkedWsOptions({ [key]: false }, caller)).toThrow(new RegExp(`wsOptions\\.${key} is reserved: the SDK sets it so that the connection is pinned`));
      }
    }
  });

  it("refuses the ws settings that shape the handshake, pointing createWebSocket at its own options", () => {
    const refusal = (options: Record<string, unknown>, caller: "createWebSocket" | "createRealtimeWebSocket"): unknown => {
      try {
        checkedWsOptions(options, caller);
      } catch (err) {
        return err;
      }
      return undefined;
    };
    const headers = refusal({ headers: { Authorization: "Bearer k" } }, "createWebSocket");
    expect(headers).toBeInstanceOf(ConfigurationError);
    expect((headers as Error).message).toMatch(/wsOptions\.headers is reserved: pass the handshake's headers in the top-level `headers` option/);
    expect((refusal({ origin: "https://app.example" }, "createWebSocket") as Error).message).toMatch(/wsOptions\.origin is reserved: set an `Origin` header in the top-level `headers` option/);
    expect((refusal({ protocol: "realtime" }, "createWebSocket") as Error).message).toMatch(/wsOptions\.protocol is reserved: .*top-level `protocols` option/);
    expect((refusal({ finishRequest: () => {} }, "createWebSocket") as Error).message).toMatch(/wsOptions\.finishRequest is reserved/);
    expect((refusal({ auth: "user:pass" }, "createWebSocket") as Error).message).toMatch(/wsOptions\.auth is reserved: .*top-level `headers` option/);
    expect((refusal({ auth: "user:pass" }, "createRealtimeWebSocket") as Error).message).toMatch(/wsOptions\.auth is reserved: .*client's credential/);
    // The realtime session has no top-level headers or subprotocols to point at.
    expect((refusal({ headers: {} }, "createRealtimeWebSocket") as Error).message).toMatch(/wsOptions\.headers is reserved: .*client's credential/);
    expect((refusal({ origin: "o" }, "createRealtimeWebSocket") as Error).message).not.toMatch(/top-level/);
    expect((refusal({ protocol: "p" }, "createRealtimeWebSocket") as Error).message).not.toMatch(/top-level/);
  });

  it("passes the other ws settings through, and ignores a reserved key that is undefined or inherited", () => {
    expect(checkedWsOptions({ perMessageDeflate: false, maxPayload: 7, handshakeTimeout: 1000 }, "createWebSocket")).toEqual({ perMessageDeflate: false, maxPayload: 7, handshakeTimeout: 1000 });
    expect(checkedWsOptions({ headers: undefined, maxPayload: 7 }, "createWebSocket")).toEqual({ headers: undefined, maxPayload: 7 });
    expect(checkedWsOptions(Object.create({ headers: { Authorization: "x" } }) as Record<string, unknown>, "createWebSocket")).toEqual({});
    expect(checkedWsOptions(undefined, "createWebSocket")).toEqual({});
    expect(() => checkedWsOptions("headers" as never, "createWebSocket")).toThrow(ConfigurationError);
    // A getter is read once: the value that is checked is the value that is passed on.
    let reads = 0;
    const shifty = Object.defineProperty({}, "headers", { enumerable: true, get: () => (reads++ === 0 ? undefined : { Authorization: "x" }) });
    expect(checkedWsOptions(shifty, "createWebSocket")).toEqual({ headers: undefined });
  });

  it("refuses any ws setting for createWebSocket on Bun, whose WebSocket takes none", () => {
    const bun = { process: { versions: { bun: "1.4.4" } } };
    expect(() => checkedWsOptions({ maxPayload: 7 }, "createWebSocket", bun)).toThrow(/Bun's WebSocket takes no `ws` client settings/);
    expect(() => checkedWsOptions({ maxPayload: 7 }, "createWebSocket", bun)).toThrow(ConfigurationError);
    expect(checkedWsOptions({}, "createWebSocket", bun)).toEqual({});
    expect(checkedWsOptions({ maxPayload: undefined }, "createWebSocket", bun)).toEqual({ maxPayload: undefined });
    expect(checkedWsOptions(undefined, "createWebSocket", bun)).toEqual({});
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

  it("removes a listener when its signal aborts, adds none for a signal that already has, and keeps once and removal working", async () => {
    const c = await client(() => TEST_PIN);
    const socket = await createWebSocket(c, "/x");
    await opened(socket);
    const seen: string[] = [];
    const controller = new AbortController();
    socket.addEventListener("message", (event) => seen.push(`live:${String(event.data)}`), { signal: controller.signal });
    socket.addEventListener("message", (event) => seen.push(`dead:${String(event.data)}`), { signal: AbortSignal.abort() });
    socket.addEventListener("message", (event) => seen.push(`once:${String(event.data)}`), { once: true, signal: controller.signal });
    const removed = (event: { readonly data: unknown }): number => seen.push(`removed:${String(event.data)}`);
    socket.addEventListener("message", removed, { signal: controller.signal });
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(3);
    socket.removeEventListener("message", removed);
    // The signal holds a hook only while the listener is registered.
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(2);
    const first = nextMessage(socket);
    socket.send("one");
    await first;
    expect(seen).toEqual(["live:echo:one", "once:echo:one"]);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(1);
    controller.abort();
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
    const second = nextMessage(socket);
    socket.send("two");
    await second;
    expect(seen).toEqual(["live:echo:one", "once:echo:one"]);
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
    const c = await createEnclaveHTTPClient(host, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" } }, { verifier: verifier(() => TEST_PIN), documentFetch: docs.fetch });
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

  it("refuses a reserved ws setting before any I/O, so that a header in it isn't silently lost", async () => {
    const docs = documents();
    const c = await client(() => TEST_PIN, docs);
    const before = connections.length;
    // Untyped code can pass what the WsOptions type omits.
    const wsOptions = { headers: { Authorization: "Bearer k" } } as never;
    await expect(createWebSocket(c, "/x", { wsOptions })).rejects.toThrow(/wsOptions\.headers is reserved/);
    await expect(createWebSocket(c, "/x", { wsOptions: { rejectUnauthorized: false } as never })).rejects.toBeInstanceOf(ConfigurationError);
    expect(connections.length).toBe(before);
    expect(docs.calls).toBe(1);
  });

  it("passes the allowed ws settings to the connection", async () => {
    const c = await client(() => TEST_PIN);
    const offered = await createWebSocket(c, "/x");
    await opened(offered);
    offered.close();
    expect(connections[connections.length - 1]!.headers["sec-websocket-extensions"]).toBeDefined();
    const socket = await createWebSocket(c, "/x", { headers: { Authorization: "Bearer k" }, wsOptions: { perMessageDeflate: false } });
    await opened(socket);
    const last = connections[connections.length - 1]!;
    expect(last.headers["sec-websocket-extensions"]).toBeUndefined();
    expect(last.headers.authorization).toBe("Bearer k");
    socket.close();
  });

  it("works in either transport mode, always directly to the enclave", async () => {
    const hpke = await (await Identity.generate()).getPublicKeyHex();
    const sealing = {
      ...verifier(() => TEST_PIN),
      verifyV3At: async () =>
        verifiedReport({
          cryptoMaterial: [
            { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: TEST_PIN },
            { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke },
          ],
          tlsPublicKeyFP: TEST_PIN,
          hpkePublicKey: hpke,
          codeDigest: "11".repeat(32),
          freshnessExpiresAt: new Date(Date.now() + 60_000),
        }),
    } as unknown as Verifier;
    const c = await createEnclaveHTTPClient(host, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "ehbp" } }, { verifier: sealing, documentFetch: documents().fetch, tls: { ca: TEST_CERT } });
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

  it("stops waiting for the verification when the call's signal aborts, rejecting with the signal's own reason", async () => {
    const c = await client(() => TEST_PIN);
    const reason = new Error("gave up");
    await expect(pinnedWebSocketOptions(c, { signal: AbortSignal.abort(reason) })).rejects.toBe(reason);
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

  describe("given to the OpenAI WebSocket clients that take ws settings, with a plain OpenAI client for the enclave", () => {
    /** What the tests use of an OpenAI WebSocket client. */
    interface Session {
      on(event: "error", listener: (err: Error) => void): unknown;
      close(): void;
    }

    /** The OpenAI WebSocket clients that build their own `ws` WebSocket to the client's base URL with the client's key. */
    const libraries = [
      { name: "ResponsesWS", path: "/v1/responses", open: (ai: OpenAI, options: WsClientOptions): Session => new ResponsesWS(ai, options) },
      { name: "LiveWS", path: "/v1/live/sessions", open: (ai: OpenAI, options: WsClientOptions): Session => new LiveWS(ai, options) },
    ];

    /** A plain OpenAI client whose base URL is the enclave that `http` is verified against, as a caller builds one for these classes. */
    function plainClient(http: EnclaveHTTPClient): OpenAI {
      return new OpenAI({ apiKey: "k", baseURL: `https://${http.enclave}/v1/` });
    }

    /** Resolves with the next connection that the server accepts after `before`, or rejects with the session's error. */
    function nextConnection(session: Session, before: number): Promise<Connection> {
      return new Promise((resolve, reject) => {
        const poll = setInterval(() => {
          if (connections.length > before) {
            clearInterval(poll);
            resolve(connections[before]!);
          }
        }, 5);
        session.on("error", (err) => {
          clearInterval(poll);
          reject(err);
        });
      });
    }

    for (const library of libraries) {
      it(`pins ${library.name} to the attested key, authenticated with the plain client's key`, async () => {
        const http = await client(() => TEST_PIN);
        const before = connections.length;
        const session = library.open(plainClient(http), await pinnedWebSocketOptions(http));
        const connection = await nextConnection(session, before);
        expect(connection.path).toBe(library.path);
        expect(connection.headers.authorization).toBe("Bearer k");
        session.close();
      });

      it(`fails ${library.name}'s handshake when the certificate carries another key, and reaches the server with nothing`, async () => {
        const docs = documents();
        const http = await client(() => OTHER_PIN, docs);
        const before = connections.length;
        const session = library.open(plainClient(http), await pinnedWebSocketOptions(http));
        const err = await nextConnection(session, before).catch((e: unknown) => e);
        expect(String((err as Error).message)).toMatch(/does not match the attested key/);
        expect(connections.length).toBe(before);
        session.close();
        expect(docs.calls).toBe(1);
        // The pin failure retired the verification the settings were pinned to.
        await pinnedWebSocketOptions(http);
        expect(docs.calls).toBe(2);
      });
    }
  });
});

describe("the openai package's WebSocket classes given a Tinfoil OpenAI client", () => {
  /** A TCP server that counts every connection made to it: any connection at all fails the tests. */
  let tripwire: TCPServer;
  let tripwireHost: string;
  let tripped = 0;

  beforeAll(async () => {
    tripwire = createTCPServer((socket) => {
      tripped++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => tripwire.listen(0, "127.0.0.1", resolve));
    tripwireHost = `localhost:${(tripwire.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => tripwire.close(() => resolve()));
  });

  /** An OpenAI client over an enclave client in TLS mode whose enclave is the tripwire; creating it sends nothing there. */
  function tinfoilClient(openaiOptions: OpenAIClientOptions, docs = documents()): Promise<OpenAIClient<EnclaveHTTPClient>> {
    return openAIOver(createEnclaveHTTPClient(tripwireHost, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" } }, { verifier: verifier(() => TEST_PIN), documentFetch: docs.fetch, tls: { ca: TEST_CERT } }), openaiOptions);
  }

  /** Each way of building one of the package's WebSocket classes from a client, with `ws` settings where the class takes them. */
  const classes: { readonly name: string; readonly open: (ai: OpenAI, options: WsClientOptions) => unknown }[] = [
    { name: "ResponsesWS", open: (ai, options) => new ResponsesWS(ai, options) },
    { name: "the beta ResponsesWS", open: (ai, options) => new BetaResponsesWS(ai, options) },
    { name: "LiveWS", open: (ai, options) => new LiveWS(ai, options) },
    { name: "LiveWS's SidebandWS", open: (ai, options) => new SidebandWS(ai, { session_id: "s" }, options) },
    { name: "LiveWS's ForksWS", open: (ai, options) => new ForksWS(ai, { session_id: "s" }, options) },
    { name: "OpenAIRealtimeWS", open: (ai, options) => new OpenAIRealtimeWS({ model: "m", options }, ai) },
    { name: "OpenAIRealtimeWS.create", open: (ai, options) => OpenAIRealtimeWS.create(ai, { model: "m", options }) },
    { name: "the beta OpenAIRealtimeWS", open: (ai, options) => new BetaOpenAIRealtimeWS({ model: "m", options }, ai) },
    { name: "the beta OpenAIRealtimeWS.create", open: (ai, options) => BetaOpenAIRealtimeWS.create(ai, { model: "m", options }) },
    { name: "OpenAIRealtimeWebSocket", open: (ai) => new OpenAIRealtimeWebSocket({ model: "m" }, ai) },
    { name: "OpenAIRealtimeWebSocket.create", open: (ai) => OpenAIRealtimeWebSocket.create(ai, { model: "m" }) },
    { name: "the beta OpenAIRealtimeWebSocket", open: (ai) => new BetaOpenAIRealtimeWebSocket({ model: "m" }, ai) },
    { name: "the beta OpenAIRealtimeWebSocket.create", open: (ai) => BetaOpenAIRealtimeWebSocket.create(ai, { model: "m" }) },
    { name: "OpenAIRealtimeTranslationWS.create", open: (ai, options) => OpenAIRealtimeTranslationWS.create(ai, { model: "m", options }) },
  ];

  /** Builds the class, synchronously or through its factory, and returns what it was refused with. */
  async function refusal(open: () => unknown): Promise<unknown> {
    try {
      await open();
    } catch (err) {
      return err;
    }
    throw new Error("the class was built");
  }

  /** Lets a connection that a class started reach the tripwire, then checks that none did. */
  async function expectNothingOpened(): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(tripped).toBe(0);
  }

  for (const { name, open } of classes) {
    it(`refuses ${name} with a ConfigurationError before any connection, whatever the credential and settings`, async () => {
      const docs = documents();
      const keyed = await tinfoilClient({ apiKey: "k" }, docs);
      const clients = [keyed, keyed.withOptions({ bearerToken: "jwt" }), await tinfoilClient({ apiKey: async () => "token" }, docs)];
      for (const ai of clients) {
        // The pinned settings don't help: the class never shows them to the client.
        for (const options of [{}, await pinnedWebSocketOptions(ai.httpClient)]) {
          const err = await refusal(() => open(ai, options));
          expect(err).toBeInstanceOf(ConfigurationError);
          expect((err as Error).message).toContain(OPENAI_WEBSOCKETS_REFUSED);
        }
      }
      await expectNothingOpened();
      // Nothing was verified again either.
      expect(docs.calls).toBe(2);
    });
  }

  it("names the supported ways in the refusal", () => {
    expect(OPENAI_WEBSOCKETS_REFUSED).toMatch(/createRealtimeWebSocket/);
    expect(OPENAI_WEBSOCKETS_REFUSED).toMatch(/createWebSocket/);
    expect(OPENAI_WEBSOCKETS_REFUSED).toMatch(/pinnedWebSocketOptions\(client\.httpClient\)/);
  });

  it("keeps the refusal in place: the hook can't be reassigned, nor the options replaced", async () => {
    const ai = await tinfoilClient({ apiKey: "k" });
    const unlocked = (OpenAI.prototype as unknown as { _buildWebSocketHeaders: unknown })._buildWebSocketHeaders;
    expect(() => ((ai as unknown as { _buildWebSocketHeaders: unknown })._buildWebSocketHeaders = unlocked)).toThrow(TypeError);
    expect(() => ((ai as unknown as { _options: unknown })._options = { apiKey: "k" })).toThrow(TypeError);
    const options = (ai as unknown as { _options: object })._options;
    expect(() => Object.defineProperty(options, "apiKey", { value: "k" })).toThrow(TypeError);
    expect(() => (options as { apiKey?: unknown }).apiKey).toThrow(ConfigurationError);
    await expect(refusal(() => new ResponsesWS(ai))).resolves.toBeInstanceOf(ConfigurationError);
    await expectNothingOpened();
  });

  it("leaves the client's own credential handling in place", async () => {
    const keyed = await tinfoilClient({ apiKey: "k" });
    expect(keyed.apiKey).toBe("k");
    expect(keyed._hasApiKeyProvider()).toBe(false);
    let calls = 0;
    const provided = await tinfoilClient({ apiKey: async () => `token-${++calls}` });
    expect(provided._hasApiKeyProvider()).toBe(true);
    let captured: string | null = null;
    expect(await provided._callApiKey((key) => (captured = key))).toBe(true);
    expect(captured).toBe("token-1");
    expect(provided.apiKey).toBe("token-1");
    // The one read that the client's own path makes is allowed, and no other.
    expect(() => (provided as unknown as { _options: { apiKey?: unknown } })._options.apiKey).toThrow(ConfigurationError);
  });
});

describe("createRealtimeWebSocket", () => {
  /** Resolves when the session's socket opens, or rejects with its error. */
  function sessionOpened(session: OpenAIRealtimeWS): Promise<void> {
    return new Promise((resolve, reject) => {
      session.socket.once("open", () => resolve());
      session.socket.once("error", reject);
    });
  }

  /** The credential the server saw on the connection a session just opened. */
  async function authorizationOf(session: OpenAIRealtimeWS): Promise<string | string[] | undefined> {
    await sessionOpened(session);
    const last = connections[connections.length - 1]!;
    expect(last.path).toBe("/v1/realtime?model=m");
    session.close();
    return last.headers.authorization;
  }

  it("opens a session on the pinned connection, authenticated with the client's key", async () => {
    const ai = await openAIClient({ apiKey: "k" });
    expect(await authorizationOf(await createRealtimeWebSocket(ai, { model: "m" }))).toBe("Bearer k");
  });

  it("authenticates a withOptions clone with the clone's bearer token, and the original with its own key", async () => {
    const ai = await openAIClient({ apiKey: "k" });
    const clone = ai.withOptions({ bearerToken: "jwt" });
    expect(await authorizationOf(await createRealtimeWebSocket(clone, { model: "m" }))).toBe("Bearer jwt");
    expect(await authorizationOf(await createRealtimeWebSocket(ai, { model: "m" }))).toBe("Bearer k");
  });

  it("calls an apiKey function for each session, and refuses a token that isn't a non-empty string before connecting", async () => {
    let calls = 0;
    const ai = await openAIClient({ apiKey: async () => `token-${++calls}` });
    expect(await authorizationOf(await createRealtimeWebSocket(ai, { model: "m" }))).toBe("Bearer token-1");
    expect(await authorizationOf(await createRealtimeWebSocket(ai, { model: "m" }))).toBe("Bearer token-2");
    // The function's declared type returns a string; untyped code can return anything, and only a non-empty string is a credential.
    for (const result of ["", undefined, null, 42]) {
      const bad = await openAIClient({ apiKey: (async () => result) as () => Promise<string> });
      const before = connections.length;
      await expect(createRealtimeWebSocket(bad, { model: "m" })).rejects.toBeInstanceOf(ConfigurationError);
      expect(connections.length).toBe(before);
    }
  });

  it("refuses a reserved ws setting before any I/O, and passes the allowed ones through", async () => {
    const docs = documents();
    const ai = await openAIClient({ apiKey: "k" }, () => TEST_PIN, docs);
    const before = connections.length;
    await expect(createRealtimeWebSocket(ai, { model: "m", wsOptions: { headers: { Authorization: "Bearer other" } } as never })).rejects.toThrow(/wsOptions\.headers is reserved/);
    await expect(createRealtimeWebSocket(ai, { model: "m", wsOptions: { checkServerIdentity: () => undefined } as never })).rejects.toBeInstanceOf(ConfigurationError);
    expect(connections.length).toBe(before);
    expect(docs.calls).toBe(1);
    const session = await createRealtimeWebSocket(ai, { model: "m", wsOptions: { perMessageDeflate: false } });
    expect(await authorizationOf(session)).toBe("Bearer k");
    expect(connections[connections.length - 1]!.headers["sec-websocket-extensions"]).toBeUndefined();
  });

  it("refuses a client no factory made, before any connection", async () => {
    const before = connections.length;
    const foreign = new OpenAI({ apiKey: "k" });
    await expect(createRealtimeWebSocket(foreign as OpenAIClient<EnclaveHTTPClient>, { model: "m" })).rejects.toThrow(/not created by its factory/);
    expect(connections.length).toBe(before);
  });
});
