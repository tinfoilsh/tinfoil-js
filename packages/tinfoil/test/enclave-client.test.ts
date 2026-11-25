/**
 * The enclave clients on local servers: option checks before any network
 * I/O, verification before the factory returns, both transport modes, a
 * proxy in front, the verification facts, the replay after a key rotation,
 * and the OpenAI client bound to the attested fetch.
 */
import { Agent } from "node:https";
import { Identity, PROTOCOL } from "ehbp";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { checkEnclaveOptions, createEnclaveHTTPClient, EnclaveHTTPClient, resolveTransport, type EnclaveClientSeams } from "../src/enclave-client.js";
import { checkTransportMode, defaultTransportMode, isBun, isServerRuntime } from "../src/internal/platform.js";
import { AttestationError, ConfigurationError, NetworkError } from "../src/errors.js";
import { OpenAIClient, type OpenAIClientOptions } from "../src/openai-client.js";
import type { EnclaveOptions, Fetch, Transport } from "../src/options.js";
import type { Trust } from "../src/trust.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verifier } from "../../verifier/src/index.js";
import { createWebSocket, pinnedWebSocketOptions } from "../src/websocket.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";
import { recordingFetch } from "./helpers/network.js";
import { paced, startTlsServer, TEST_CERT, TEST_PIN, type TlsServer } from "./helpers/tls-server.js";
import { expectWithOptionsRefusesTransportOptions } from "./helpers/transport-options.js";
import { openAIOver } from "./helpers/openai.js";
import { lastFacts, verifiedReport } from "./helpers/report.js";

let tls: TlsServer;
let ehbp: EhbpServer;
let sseEnded = false;
/** The runtime's fetch as it was before any test replaces the global, for a network fetch to forward over. */
const runtimeFetch: Fetch = globalThis.fetch.bind(globalThis);

/** A trust that the test verifiers ignore, as a caller-authorized config needs no pin. */
const AUTHORIZED: Trust = { kind: "authorizedBy", authorize: () => undefined };

/** A verifier whose verifications carry the given keys; `keys` is read per verification so a test can rotate them. */
function verifier(keys: () => { tls?: string; hpke?: string }): Verifier {
  return {
    checkPinVerifiability: ({ repo = "" }: { repo?: string }) => {
      if (repo.includes(" ")) throw new UsageError(`bad repo ${repo}`);
    },
    verifyV3At: async () => {
      const k = keys();
      const material = [
        ...(k.tls === undefined ? [] : [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: k.tls }]),
        ...(k.hpke === undefined ? [] : [{ id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: k.hpke }]),
      ];
      return verifiedReport({
        cryptoMaterial: material.map((m) => ({ ...m })),
        tlsPublicKeyFP: k.tls,
        hpkePublicKey: k.hpke,
        codeDigest: "11".repeat(32),
        freshnessExpiresAt: new Date(Date.now() + 60_000),
      });
    },
  } as unknown as Verifier;
}

/** A document fetch that answers any attestation request and counts the calls. */
function documents(): { fetch: Fetch; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetch: async (input) => {
      calls.push(String(input));
      return new Response(new Uint8Array([1]));
    },
  };
}

beforeAll(async () => {
  tls = await startTlsServer((seen) => {
    if (seen.path === "/sse") {
      sseEnded = false;
      return { headers: { "content-type": "text/event-stream" }, body: paced(["data: a\n\n", "data: b\n\n"], 60, () => (sseEnded = true)) };
    }
    if (seen.path === "/v1/chat/completions") {
      return { headers: { "content-type": "application/json" }, body: JSON.stringify(completion("pinned")) };
    }
    return { headers: { "content-type": "application/json" }, body: JSON.stringify({ path: seen.path, enclave: seen.headers["x-tinfoil-enclave-url"] ?? null }) };
  });
  ehbp = await startEhbpServer((seen) => {
    if (seen.path.endsWith("/chat/completions")) {
      return { headers: { "content-type": "application/json" }, body: JSON.stringify(completion(new TextDecoder().decode(seen.body).length > 0 ? "sealed" : "plain")) };
    }
    return {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path: seen.path, sealed: seen.sealed, enclave: seen.headers["x-tinfoil-enclave-url"] ?? null, text: new TextDecoder().decode(seen.body) }),
    };
  });
});

afterAll(async () => {
  await Promise.all([tls.close(), ehbp.close()]);
});

function completion(content: string): unknown {
  return {
    id: "chatcmpl-1",
    object: "chat.completion",
    created: 1,
    model: "test",
    choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
  };
}

describe("EnclaveHTTPClient.create", () => {
  it("defaults the transport mode by platform and rejects an unknown one", () => {
    expect(resolveTransport(undefined).mode).toBe("tls");
    expect(resolveTransport({ kind: "ehbp" }).mode).toBe("ehbp");
    expect(() => resolveTransport({ kind: "quic" } as unknown as Transport)).toThrow(/transport must have kind/);
  });

  it("treats only a runtime that identifies itself as Node or Bun as a server, and anything else as a browser", () => {
    expect(isServerRuntime({ process: { versions: { node: "22.0.0" } } })).toBe(true);
    expect(isServerRuntime({ process: { versions: { bun: "1.2.0" } } })).toBe(true);
    expect(isServerRuntime({ Bun: {} })).toBe(true);
    // A worker has neither window nor document, only self; it is a browser all the same.
    const worker = { self: {} } as unknown as Parameters<typeof isServerRuntime>[0];
    expect(isServerRuntime(worker)).toBe(false);
    expect(defaultTransportMode(worker)).toBe("ehbp");
    expect(() => checkTransportMode("tls", worker)).toThrow(/browsers don't expose/);
    expect(() => checkTransportMode("ehbp", worker)).not.toThrow();
    expect(isServerRuntime({ process: { versions: {} } })).toBe(false);
  });

  it("tells Bun from Node by the version Bun reports, and from a runtime with no process at all", () => {
    expect(isBun({ process: { versions: { bun: "1.2.0" } } })).toBe(true);
    expect(isBun({ process: { versions: { node: "22.0.0" } } })).toBe(false);
    expect(isBun({ process: { versions: {} } })).toBe(false);
    expect(isBun({})).toBe(false);
    expect(isBun()).toBe(Boolean(process.versions.bun));
  });

  it("checks its options before fetching anything", async () => {
    const docs = documents();
    const network = recordingFetch(runtimeFetch);
    const seams: EnclaveClientSeams = { documentFetch: docs.fetch, verifier: verifier(() => ({ tls: TEST_PIN })) };
    const repo: Trust = { kind: "repoPin", repo: "tinfoilsh/repo" };
    const cases: [string, Trust, EnclaveOptions][] = [
      ["", repo, {}],
      ["enclave.example", repo, { transport: { kind: "quic" as never } as Transport }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "http://proxy.example/" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "https://proxy.example/v1/?key=1" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "https://proxy.example/v1/?" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "https://proxy.example/v1/#frag" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "https://proxy.example/v1/#" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "https://user:pw@proxy.example/" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "/v1" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "ftp://proxy.example/" } }],
      // A proxy on the enclave's own origin is no proxy, with or without the default port.
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "https://enclave.example/relay" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: "https://enclave.example:443" } }],
      ["enclave.example", repo, { transport: { kind: "ehbp", fetch: "fetch" as never } }],
      ["enclave.example", repo, { transport: "ehbp" as never }],
      ["enclave.example", repo, { transport: { kind: "ehbp", proxyURL: null } as never }],
      ["enclave.example", repo, { transport: { kind: 1n } as never }],
      ["enclave.example", repo, { transport: { kind: Symbol("tls") } as never }],
      ["enclave.example", repo, { transport: { proxyURL: "https://proxy.example/" } as never }],
      ["enclave.example", { kind: "repoPin", repo: "" }, {}],
      ["enclave.example", { kind: "projectPin", project: "org/project", registryIDs: [] }, {}],
      ["enclave.example", { kind: "eitherPin", repo: "tinfoilsh/repo" } as unknown as Trust, {}],
      ["enclave.example", { kind: "pin", repo: "tinfoilsh/repo" } as unknown as Trust, {}],
      ["enclave.example", { repo: "tinfoilsh/repo" } as unknown as Trust, {}],
      ["enclave.example", undefined as unknown as Trust, {}],
    ];
    for (const [host, trust, options] of cases) {
      await expect(createEnclaveHTTPClient(host, trust, options, seams), `${host} ${JSON.stringify(trust)}`).rejects.toBeInstanceOf(ConfigurationError);
    }
    // A policy, a malformed reference and an empty registry list are checked by the verifier built from them, before any fetch.
    await expect(createEnclaveHTTPClient("enclave.example", repo, { policy: { freshnessMaxAgeMs: -1 } }, { documentFetch: docs.fetch })).rejects.toBeInstanceOf(ConfigurationError);
    await expect(createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "bad repo" }, {}, { documentFetch: docs.fetch })).rejects.toBeInstanceOf(ConfigurationError);
    await expect(createEnclaveHTTPClient("enclave.example", { kind: "signedBy", keys: [] }, {}, { documentFetch: docs.fetch })).rejects.toBeInstanceOf(ConfigurationError);
    await expect(createEnclaveHTTPClient("enclave.example", { kind: "projectPin", project: "org/project", registryIDs: [] }, {}, { documentFetch: docs.fetch })).rejects.toThrow(/registryIDs must not be empty/);
    expect(docs.calls).toHaveLength(0);
    expect(network.seen).toHaveLength(0);
  });

  it("resolves the transport, keeping the EHBP fetch and the proxy inside the EHBP variant", () => {
    const network = recordingFetch(runtimeFetch);
    const node = { process: { versions: { node: "22.0.0" } } };
    expect(checkEnclaveOptions("enclave.example", {}, node)).toEqual({ mode: "tls", proxyURL: "" });
    expect(checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", fetch: network.fetch } })).toEqual({ mode: "ehbp", proxyURL: "", fetch: network.fetch });
    expect(checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", proxyURL: "https://proxy.example/relay" } })).toEqual({ mode: "ehbp", proxyURL: "https://proxy.example/relay/" });
    expect(checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", proxyURL: "" } })).toEqual({ mode: "ehbp", proxyURL: "" });
    expect(checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", proxyURL: "http://localhost:8080/relay" } }).proxyURL).toBe("http://localhost:8080/relay/");
    expect(checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", proxyURL: "http://127.0.0.1:8080/relay" } }).proxyURL).toBe("http://127.0.0.1:8080/relay/");
    expect(checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", proxyURL: "http://[::1]:8080/relay" } }).proxyURL).toBe("http://[::1]:8080/relay/");
    for (const proxyURL of ["http://app.localhost/relay", "http://0.0.0.0:8080/relay"]) {
      expect(() => checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", proxyURL } }), proxyURL).toThrow(/HTTP is allowed only for localhost/);
    }
    expect(() => checkEnclaveOptions("enclave.example", { transport: { kind: "ehbp", proxyURL: "https://enclave.example:443/" } })).toThrow(/enclave's own origin; leave proxyURL unset/);
    expect(() => resolveTransport({ kind: "quic" } as unknown as Transport)).toThrow(/transport must have kind "tls" or "ehbp", not "quic"/);
    // A browser resolves no transport to EHBP; TLS is refused for the browser's own reason.
    const worker = { self: {} } as unknown as Parameters<typeof checkEnclaveOptions>[2];
    expect(checkEnclaveOptions("enclave.example", {}, worker)).toEqual({ mode: "ehbp", proxyURL: "" });
    expect(() => checkEnclaveOptions("enclave.example", { transport: { kind: "tls" } }, worker)).toThrow(/browsers don't expose/);
    expect(network.seen).toHaveLength(0);
  });

  it("verifies before returning and reports a failed verification without constructing the client", async () => {
    const docs = documents();
    const pending = createEnclaveHTTPClient(tls.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" } }, { verifier: verifier(() => ({})), documentFetch: docs.fetch, sleep: async () => {} });
    await expect(pending).rejects.toBeInstanceOf(AttestationError);
    expect(docs.calls.length).toBe(2);
  });

  it("closes the transport when the signal cuts the verification short, so what that verification binds is released when it finishes", async () => {
    const destroyed = vi.spyOn(Agent.prototype, "destroy");
    try {
      let begun!: () => void;
      let serve!: () => void;
      const started = new Promise<void>((resolve) => (begun = resolve));
      const held = new Promise<void>((resolve) => (serve = resolve));
      const documentFetch: Fetch = async () => {
        begun();
        await held;
        return new Response(new Uint8Array([1]));
      };
      const controller = new AbortController();
      const pending = createEnclaveHTTPClient(
        tls.host,
        { kind: "repoPin", repo: "tinfoilsh/repo" },
        { transport: { kind: "tls" }, signal: controller.signal },
        { verifier: verifier(() => ({ tls: TEST_PIN })), documentFetch, tls: { ca: TEST_CERT } });
      await started;
      const reason = new Error("gave up");
      controller.abort(reason);
      await expect(pending).rejects.toBe(reason);
      expect(destroyed).not.toHaveBeenCalled();
      // The verification finishes after the factory rejected; the pool it binds is destroyed rather than kept.
      serve();
      await vi.waitFor(() => expect(destroyed).toHaveBeenCalledTimes(1));
    } finally {
      destroyed.mockRestore();
    }
  });
});

describe("EnclaveHTTPClient over TLS", () => {
  let client: EnclaveHTTPClient;
  let docs: ReturnType<typeof documents>;

  beforeAll(async () => {
    docs = documents();
    client = await createEnclaveHTTPClient(
      tls.host,
      { kind: "repoPin", repo: "tinfoilsh/repo" },
      { transport: { kind: "tls" } },
      { verifier: verifier(() => ({ tls: TEST_PIN })), documentFetch: docs.fetch, tls: { ca: TEST_CERT } });
  });

  it("is verified on creation and exposes the facts", async () => {
    expect(docs.calls).toEqual([`https://${tls.host}/.well-known/tinfoil-attestation?nonce=${docs.calls[0]!.split("nonce=")[1]}`]);
    expect(Object.keys(client)).toEqual(["fetch", "baseURL", "enclave"]);
    expect(() => ((client as { enclave: string }).enclave = "evil.example")).toThrow(TypeError);
    expect(client.enclave).toBe(tls.host);
    expect(client.trust).toEqual({ kind: "repoPin", repo: "tinfoilsh/repo" });
    expect(Object.isFrozen(client.trust)).toBe(true);
    expect(client.baseURL).toBe(`https://${tls.host}/`);
    expect(lastFacts(client)?.tlsPublicKeyFP).toBe(TEST_PIN);
    expect((await client.ensureVerified()).verifiedFacts?.codeDigest).toBe("11".repeat(32));
    expect(docs.calls).toHaveLength(1);
    await client.reverify();
    expect(docs.calls).toHaveLength(2);
  });

  it("stops a verification call waiting when its signal aborts, rejecting with the signal's own reason and leaving the verification in place", async () => {
    const reason = new Error("gave up");
    const signal = AbortSignal.abort(reason);
    await expect(client.reverify({ signal })).rejects.toBe(reason);
    await expect(client.ensureVerified({ signal })).rejects.toBe(reason);
    expect(lastFacts(client)?.tlsPublicKeyFP).toBe(TEST_PIN);
    expect(docs.calls).toHaveLength(2);
  });

  it("sends over the pinned connection, refuses other origins and plaintext, and omits the proxy header", async () => {
    const res = await client.fetch(`${tls.origin}/models`);
    expect(await res.json()).toEqual({ path: "/models", enclave: null });
    await expect(client.fetch("https://other.example/models")).rejects.toThrow(/client is bound to enclave/);
    await expect(client.fetch(`http://${tls.host}/models`)).rejects.toBeInstanceOf(ConfigurationError);
  });

  it("sends request bodies as they are, never adding or changing a user_cache_secret member", async () => {
    for (const body of ['{"model":"test","messages":[]}', '{"model":"test","user_cache_secret":""}', '{"model":"test","user_cache_secret":"mine"}']) {
      await client.fetch(`https://${tls.host}/v1/chat/completions`, { method: "POST", body, headers: { "content-type": "application/json" } });
      expect(new TextDecoder().decode(tls.seen[tls.seen.length - 1]!.body)).toBe(body);
    }
  });

  it("streams a response as the server writes it", async () => {
    const res = await client.fetch(`${tls.origin}/sse`);
    const reader = res.body!.getReader();
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toBe("data: a\n\n");
    expect(sseEnded).toBe(false);
    await reader.cancel();
  });

  it("backs an OpenAI client on the enclave's /v1/ API over the pinned connection", async () => {
    const ai = await openAIOver(createEnclaveHTTPClient(tls.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" } }, { verifier: verifier(() => ({ tls: TEST_PIN })), documentFetch: docs.fetch, tls: { ca: TEST_CERT } }), { apiKey: "k" });
    expect(ai.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(ai.httpClient).toBeInstanceOf(EnclaveHTTPClient);
    const completion = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(completion.choices[0]!.message.content).toBe("pinned");
    expect(tls.seen[tls.seen.length - 1]!.headers.authorization).toBe("Bearer k");
    expect(() => new OpenAIClient(Symbol("x") as never)).toThrow(ConfigurationError);
  });

  it("sets the base URL itself, after the caller's options, so that a base URL from the options or the environment has no effect", async () => {
    const saved = process.env.OPENAI_BASE_URL;
    process.env.OPENAI_BASE_URL = "https://evil.example/v1/";
    try {
      const options = { apiKey: "k", baseURL: "https://evil.example/v1/", dataResidency: "eu" } as unknown as OpenAIClientOptions;
      for (const ai of [new OpenAIClient(client, options), new OpenAIClient(client, { apiKey: "k" })]) {
        expect(ai.baseURL).toBe(`https://${tls.host}/v1/`);
        const completion = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
        expect(completion.choices[0]!.message.content).toBe("pinned");
        expect(tls.seen[tls.seen.length - 1]!.path).toBe("/v1/chat/completions");
      }
      const custom = new OpenAIClient(client, { apiKey: "k", apiPath: "/openai/v1" });
      expect(custom.baseURL).toBe(`https://${tls.host}/openai/v1/`);
      // The API path configures this client; the OpenAI client never sees it.
      expect((custom as unknown as { _options: Record<string, unknown> })._options).not.toHaveProperty("apiPath");
      expect(custom.withOptions({ timeout: 1 }).baseURL).toBe(`https://${tls.host}/openai/v1/`);
      expect(custom.withOptions({ apiPath: "/v2/" }).baseURL).toBe(`https://${tls.host}/v2/`);
    } finally {
      if (saved === undefined) delete process.env.OPENAI_BASE_URL;
      else process.env.OPENAI_BASE_URL = saved;
    }
  });

  it("refuses an invalid API path without any network I/O", () => {
    const before = tls.seen.length;
    for (const apiPath of ["", "v1/", "//evil.example/v1", "https://evil.example/v1", "/v1?x=1", "/v1#f", "/v1/../admin", "/v1/./x", "/v1/%2e%2e/x", "/v1/.%2E/x", "/v1%2fadmin", "/v1\\..\\x", "/v1/ x", "/v1/%zz", 7 as unknown as string]) {
      expect(() => new OpenAIClient(client, { apiKey: "k", apiPath }), String(apiPath)).toThrow(ConfigurationError);
    }
    expect(() => new OpenAIClient(client, { apiKey: "k", apiPath: "" })).toThrow(/it is empty; leave apiPath out for the default/);
    expect(() => new OpenAIClient(client, { apiKey: "k", apiPath: null as unknown as string })).toThrow(/it must be a string/);
    // The API path was a separate argument before the OpenAI options; untyped code that still passes three is refused.
    expect(() => new (OpenAIClient as unknown as new (...args: unknown[]) => unknown)(client, { apiPath: "/v1/" }, { apiKey: "k" })).toThrow(/pass apiPath among the OpenAI options/);
    expect(tls.seen.length).toBe(before);
  });

  it("keeps the attested transport and its own settings through option changes and clones", async () => {
    const ai = await openAIOver(createEnclaveHTTPClient(tls.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" } }, { verifier: verifier(() => ({ tls: TEST_PIN })), documentFetch: docs.fetch, tls: { ca: TEST_CERT } }), { apiKey: "k", timeout: 1234, maxRetries: 0, defaultHeaders: { "x-custom": "kept" }, dangerouslyAllowBrowser: true });
    const evil: Fetch = async () => new Response("intercepted");
    const fetchOf = (client: unknown): Fetch => (client as { fetch: Fetch }).fetch;
    expect(() => ((ai as unknown as { fetch: Fetch }).fetch = evil)).toThrow(TypeError);
    expect(() => ((ai as unknown as { baseURL: string }).baseURL = "https://evil.example/")).toThrow(TypeError);
    expect(() => ((ai as unknown as { httpClient: unknown }).httpClient = {})).toThrow(TypeError);
    const clone = ai.withOptions({ apiKey: "k2", baseURL: "https://evil.example/", fetch: evil } as Parameters<typeof ai.withOptions>[0]);
    expect(clone).toBeInstanceOf(OpenAIClient);
    expect(clone.httpClient).toBe(ai.httpClient);
    expect(clone.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(fetchOf(clone)).toBe(fetchOf(ai));
    expect(clone.timeout).toBe(1234);
    expect(clone.maxRetries).toBe(0);
    expect((clone as unknown as { _options: { dangerouslyAllowBrowser?: boolean } })._options.dangerouslyAllowBrowser).toBe(true);
    const completion = await clone.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(completion.choices[0]!.message.content).toBe("pinned");
    expect(tls.seen[tls.seen.length - 1]!.headers.authorization).toBe("Bearer k2");
    expect(tls.seen[tls.seen.length - 1]!.headers["x-custom"]).toBe("kept");
    const again = clone.withOptions({ timeout: 5_000, defaultHeaders: { "x-custom": "changed", "x-added": "new" } });
    expect(again.timeout).toBe(5_000);
    expect(again.apiKey).toBe("k2");
    expect(again.maxRetries).toBe(0);
    await again.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(tls.seen[tls.seen.length - 1]!.headers["x-custom"]).toBe("changed");
    expect(tls.seen[tls.seen.length - 1]!.headers["x-added"]).toBe("new");
    expect(fetchOf(again)).toBe(fetchOf(ai));
  });

  it("refuses the options that would choose another transport in withOptions, and keeps the others", async () => {
    const options: EnclaveOptions = { transport: { kind: "tls" } };
    // An option the caller holds as undefined or null is unset, as the OpenAI client takes it.
    const unset = { dataResidency: undefined, provider: null, workloadIdentity: undefined, credential: null, x509Transport: null };
    const ai = await openAIOver(createEnclaveHTTPClient(tls.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, options, { documentFetch: docs.fetch, tls: { ca: TEST_CERT }, verifier: verifier(() => ({ tls: TEST_PIN })) }), { apiKey: "k", organization: "org", defaultQuery: { q: "1" }, defaultHeaders: { "x-custom": "kept" }, timeout: 1234, maxRetries: 0, ...unset } as OpenAIClientOptions);
    expectWithOptionsRefusesTransportOptions(ai);
    const clone = ai.withOptions({ timeout: 5_000, organization: "org2" });
    for (const [client, organization] of [[ai, "org"], [clone, "org2"]] as const) {
      // The server echoes the path it was sent on the pinned connection.
      expect(await client.get("/echo")).toEqual({ path: "/v1/echo?q=1", enclave: null });
      const last = tls.seen[tls.seen.length - 1]!;
      expect(last.headers["openai-organization"]).toBe(organization);
      expect(last.headers["x-custom"]).toBe("kept");
    }
    expect([ai.timeout, ai.maxRetries, clone.timeout, clone.maxRetries]).toEqual([1234, 0, 5_000, 0]);
  });

  it("lets a clone replace the credential in either form", async () => {
    const options: EnclaveOptions = { transport: { kind: "tls" } };
    const seams = { documentFetch: docs.fetch, tls: { ca: TEST_CERT }, verifier: verifier(() => ({ tls: TEST_PIN })) };
    const allowed = (client: unknown): boolean | undefined => (client as { _options: { dangerouslyAllowBrowser?: boolean } })._options.dangerouslyAllowBrowser;
    const withToken = await openAIOver(createEnclaveHTTPClient(tls.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, options, seams), { bearerToken: "jwt" });
    expect(withToken.apiKey).toBe("jwt");
    expect(allowed(withToken)).toBe(true);
    const keyed = withToken.withOptions({ apiKey: "k" });
    expect(keyed.apiKey).toBe("k");
    expect(allowed(keyed)).toBeUndefined();
    const withKey = await openAIOver(createEnclaveHTTPClient(tls.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, options, seams), { apiKey: "k" });
    const tokened = withKey.withOptions({ bearerToken: "jwt2" });
    expect(tokened.apiKey).toBe("jwt2");
    expect(allowed(tokened)).toBe(true);
    expect(tokened.withOptions({ bearerToken: "jwt3" }).apiKey).toBe("jwt3");
  });
});

describe("EnclaveHTTPClient.close over TLS", () => {
  /** A server of this group's own, so the connections counted are only those of the clients made here. */
  let own: TlsServer;
  const options: EnclaveOptions = { transport: { kind: "tls" } };
  const pinned = verifier(() => ({ tls: TEST_PIN }));

  beforeAll(async () => {
    own = await startTlsServer((seen) =>
      seen.path === "/sse" ? { headers: { "content-type": "text/event-stream" }, body: paced(["data: a\n\n", "data: b\n\n"], 2_000) } : { body: "ok" },
    );
  });

  afterAll(async () => {
    await own.close();
  });

  it("closes the pooled connection, keeps the last verification, refuses further use, and closes again without effect", async () => {
    const docs = documents();
    const client = await createEnclaveHTTPClient(own.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, options, { documentFetch: docs.fetch, tls: { ca: TEST_CERT }, verifier: pinned });
    expect(await (await client.fetch(`${own.origin}/models`)).text()).toBe("ok");
    expect(own.openConnections()).toBe(1);
    await client.close();
    await vi.waitFor(() => expect(own.openConnections()).toBe(0));
    await client.close();
    expect(lastFacts(client)?.tlsPublicKeyFP).toBe(TEST_PIN);
    for (const call of [client.fetch(`${own.origin}/models`), client.ensureVerified(), client.reverify(), createWebSocket(client, "/x"), pinnedWebSocketOptions(client)]) {
      await expect(call).rejects.toBeInstanceOf(ConfigurationError);
      await expect(call).rejects.toThrow(/client is closed/);
    }
    expect(docs.calls).toHaveLength(1);
    expect(own.openConnections()).toBe(0);
  });

  it("ends a response still streaming over the pooled connection", async () => {
    const client = await createEnclaveHTTPClient(own.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, options, { documentFetch: documents().fetch, tls: { ca: TEST_CERT }, verifier: pinned });
    const reader = (await client.fetch(`${own.origin}/sse`)).body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("data: a\n\n");
    await client.close();
    await expect(reader.read()).rejects.toThrow();
    await vi.waitFor(() => expect(own.openConnections()).toBe(0));
  });

  it("closes at the end of an `await using` block, and an OpenAI client closes the HTTP client under it", async () => {
    const client = await createEnclaveHTTPClient(own.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, options, { documentFetch: documents().fetch, tls: { ca: TEST_CERT }, verifier: pinned });
    {
      await using scoped = client;
      expect(scoped.lastVerificationAttempt()).toBeDefined();
    }
    await expect(client.ensureVerified()).rejects.toThrow(/client is closed/);

    const ai = await openAIOver(createEnclaveHTTPClient(own.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, options, { documentFetch: documents().fetch, tls: { ca: TEST_CERT }, verifier: pinned }), { apiKey: "k", maxRetries: 0 });
    const clone = ai.withOptions({ apiKey: "k2" });
    {
      await using scoped = clone;
      expect(scoped.httpClient).toBe(ai.httpClient);
    }
    await expect(ai.httpClient.ensureVerified()).rejects.toThrow(/client is closed/);
    await expect(ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] })).rejects.toThrow();
  });
});

describe("EnclaveHTTPClient after a failed re-verification over TLS", () => {
  /** A server of this group's own, so the connections and requests counted are only those of the clients made here. */
  let own: TlsServer;

  beforeAll(async () => {
    own = await startTlsServer(() => ({ body: "ok" }));
  });

  afterAll(async () => {
    await own.close();
  });

  /** A client whose next verification fails as `fail.next` says: the verifier rejecting the document, or the document fetch failing. */
  async function failingClient() {
    const fail: { next: "attestation" | "network" | undefined } = { next: undefined };
    const docs = documents();
    const pinned = verifier(() => ({ tls: TEST_PIN }));
    const seams: EnclaveClientSeams = {
      tls: { ca: TEST_CERT },
      sleep: async () => {},
      verifier: {
        ...pinned,
        verifyV3At: async (...args: Parameters<Verifier["verifyV3At"]>) => {
          if (fail.next === "attestation") throw new Error("nonce mismatch");
          return pinned.verifyV3At(...args);
        },
      } as unknown as Verifier,
      documentFetch: async (input, init) => {
        if (fail.next === "network") throw new TypeError("fetch failed");
        return docs.fetch(input, init);
      },
    };
    const client = await createEnclaveHTTPClient(own.host, { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" } }, seams);
    return { client, fail, docs };
  }

  it("stops sending under the cached verification after an attestation failure, closes its pooled connection, and recovers on a later request", async () => {
    const { client, fail, docs } = await failingClient();
    const seen = own.seen.length;
    expect(await (await client.fetch(`${own.origin}/models`)).text()).toBe("ok");
    expect(own.openConnections()).toBe(1);

    fail.next = "attestation";
    await expect(client.reverify()).rejects.toThrow(AttestationError);
    await vi.waitFor(() => expect(own.openConnections()).toBe(0));
    await expect(client.fetch(`${own.origin}/models`)).rejects.toThrow(AttestationError);
    expect(own.seen.length).toBe(seen + 1);

    fail.next = undefined;
    const verified = docs.calls.length;
    expect(await (await client.fetch(`${own.origin}/models`)).text()).toBe("ok");
    expect(docs.calls.length).toBe(verified + 1);
    expect(own.seen.length).toBe(seen + 2);
    await client.close();
  });

  it("keeps sending under the cached verification and its pooled connection after a network failure, without verifying again", async () => {
    const { client, fail, docs } = await failingClient();
    expect(await (await client.fetch(`${own.origin}/models`)).text()).toBe("ok");
    fail.next = "network";
    await expect(client.reverify()).rejects.toThrow(NetworkError);
    const verified = docs.calls.length;
    expect(await (await client.fetch(`${own.origin}/models`)).text()).toBe("ok");
    expect(docs.calls.length).toBe(verified);
    expect(own.openConnections()).toBe(1);
    await client.close();
  });
});

describe("EnclaveHTTPClient over EHBP", () => {
  it("seals requests to the enclave's key and reaches the enclave through a proxy with the enclave header", async () => {
    const docs = documents();
    // The network reaches the proxy and nothing else, so a request to the enclave's own origin is seen leaving and refused here, not sent anywhere.
    const network = recordingFetch(async (input, init) => {
      const url = new URL(String(input));
      if (url.origin === ehbp.origin) return runtimeFetch(input, init);
      throw new TypeError(`no route to ${url.host}`);
    });
    const proxied = await createEnclaveHTTPClient(
      "enclave.example",
      AUTHORIZED,
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/`, fetch: network.fetch } },
      { verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex })), documentFetch: docs.fetch });
    expect(proxied.baseURL).toBe(`${ehbp.origin}/`);
    expect(proxied.enclave).toBe("enclave.example");
    expect(proxied.trust).toEqual(AUTHORIZED);
    const res = await proxied.fetch(`${ehbp.origin}/echo`, { method: "POST", body: "prompt" });
    expect(await res.json()).toEqual({ path: "/echo", sealed: true, enclave: "https://enclave.example", text: "prompt" });
    const bodiless = await (await proxied.fetch(`${ehbp.origin}/echo`)).json();
    expect(bodiless.sealed).toBe(false);
    // The enclave's own origin is allowed beside the proxy's: the request leaves sealed, and fails only where the network has no route to it.
    const plaintext = "a prompt that only the enclave may read";
    await expect(proxied.fetch("https://enclave.example/echo", { method: "POST", body: plaintext })).rejects.toThrow(/no route to enclave\.example/);
    expect(network.seen.map((s) => s.url)).toEqual([`${ehbp.origin}/echo`, `${ehbp.origin}/echo`, "https://enclave.example/echo"]);
    expect(network.seen[2]!.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER)).toBe(true);
    expect(network.seen[2]!.body).not.toContain(plaintext);
    await expect(proxied.fetch("https://other.example/echo")).rejects.toThrow(/client is bound to enclave/);
    expect(network.seen).toHaveLength(3);
  });

  it("sends sealed requests through the fetch option and opens their responses, while attestation documents keep the runtime's fetch", async () => {
    const network = recordingFetch(runtimeFetch);
    // The runtime's fetch answers attestation requests and nothing else; sealed requests must not reach it.
    const runtime = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.includes("/.well-known/tinfoil-attestation")) return new Response(new Uint8Array([1]));
      return runtimeFetch(input, init);
    });
    try {
      const client = await createEnclaveHTTPClient(
        "enclave.example",
        AUTHORIZED,
        { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/`, fetch: network.fetch } },
        { verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex })) });
      expect(runtime.mock.calls.map(([input]) => String(input instanceof Request ? input.url : input))).toEqual([expect.stringMatching(/^https:\/\/enclave\.example\/\.well-known\/tinfoil-attestation\?nonce=/)]);
      expect(network.seen).toHaveLength(0);

      const res = await client.fetch(`${ehbp.origin}/echo`, { method: "POST", body: "prompt", headers: { authorization: "Bearer k" } });
      expect(await res.json()).toEqual({ path: "/echo", sealed: true, enclave: "https://enclave.example", text: "prompt" });
      expect(network.seen).toHaveLength(1);
      const sealed = network.seen[0]!;
      expect(sealed.url).toBe(`${ehbp.origin}/echo`);
      expect(sealed.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER)).toBe(true);
      expect(sealed.headers.get("x-tinfoil-enclave-url")).toBe("https://enclave.example");
      expect(sealed.headers.get("authorization")).toBe("Bearer k");
      expect(sealed.body).not.toContain("prompt");
      expect(sealed.body.length).toBeGreaterThan("prompt".length);

      const bodiless = await (await client.fetch(`${ehbp.origin}/echo`, { headers: { authorization: "Bearer k" } })).json();
      expect(bodiless).toMatchObject({ path: "/echo", sealed: false });
      expect(network.seen).toHaveLength(2);
      expect(network.seen[1]!.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER)).toBe(false);
      expect(network.seen[1]!.headers.get("authorization")).toBe("Bearer k");
      expect(network.seen[1]!.body).toBe("");

      // Nothing but the attestation document went through the runtime's fetch.
      expect(runtime).toHaveBeenCalledTimes(1);
    } finally {
      runtime.mockRestore();
    }
  });

  it("ends the base URL with a slash, keeps requests on its origin, and gives an OpenAI client the same paths either way", async () => {
    const options = (baseURL: string): EnclaveOptions => ({ transport: { kind: "ehbp", proxyURL: baseURL } });
    const sealing = verifier(() => ({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }));
    const bare = await createEnclaveHTTPClient("enclave.example", AUTHORIZED, options(ehbp.origin), { documentFetch: documents().fetch, verifier: sealing });
    expect(bare.baseURL).toBe(`${ehbp.origin}/`);
    // The report names the enclave that the client verified, not the proxy that requests go through.
    expect(bare.currentVerification()?.toJSON().metadata.host).toBe("enclave.example");
    expect((await (await bare.fetch(new URL("echo", bare.baseURL), { method: "POST", body: "under" })).json()).text).toBe("under");
    await expect(bare.fetch("https://other.example/echo")).rejects.toThrow(/client is bound to enclave/);
    const slashed = await createEnclaveHTTPClient("enclave.example", AUTHORIZED, options(`${ehbp.origin}/`), { documentFetch: documents().fetch, verifier: sealing });
    expect(slashed.baseURL).toBe(`${ehbp.origin}/`);
    const padded = await createEnclaveHTTPClient("enclave.example", AUTHORIZED, options(`  ${ehbp.origin}/v1  `), { documentFetch: documents().fetch, verifier: sealing });
    expect(padded.baseURL).toBe(`${ehbp.origin}/v1/`);

    // The proxy's path is where it is mounted; the API path joins under it, whether or not the proxy URL ends with a slash.
    const paths: string[] = [];
    for (const [base, apiPath, want] of [
      [`${ehbp.origin}/relay`, undefined, `${ehbp.origin}/relay/v1/`],
      [`${ehbp.origin}/relay/`, undefined, `${ehbp.origin}/relay/v1/`],
      [`${ehbp.origin}/relay`, "/openai/v1", `${ehbp.origin}/relay/openai/v1/`],
      [`${ehbp.origin}/relay/`, "/openai/v1/", `${ehbp.origin}/relay/openai/v1/`],
    ] as const) {
      const ai = await openAIOver(createEnclaveHTTPClient("enclave.example", AUTHORIZED, options(base), { documentFetch: documents().fetch, verifier: sealing }), { apiKey: "k", ...(apiPath === undefined ? {} : { apiPath }) });
      expect(ai.baseURL).toBe(want);
      const completion = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
      expect(completion.choices[0]!.message.content).toBe("sealed");
      paths.push(ehbp.seen[ehbp.seen.length - 1]!.path);
    }
    expect(paths).toEqual(["/relay/v1/chat/completions", "/relay/v1/chat/completions", "/relay/openai/v1/chat/completions", "/relay/openai/v1/chat/completions"]);
  });

  it("replays once after the enclave rotates its key, re-verifying in between", async () => {
    const stale = await (await Identity.generate()).getPublicKeyHex();
    let verified = 0;
    const docs = documents();
    const client = await createEnclaveHTTPClient(
      "enclave.example",
      AUTHORIZED,
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` } },
      { verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: verified++ === 0 ? stale : ehbp.publicKeyHex })), documentFetch: docs.fetch, sleep: async () => {} });
    expect(lastFacts(client)?.hpkePublicKey).toBe(stale);
    const before = ehbp.seen.length;
    const res = await client.fetch(`${ehbp.origin}/echo`, { method: "POST", body: "again" });
    expect((await res.json()).text).toBe("again");
    expect(verified).toBe(2);
    expect(ehbp.seen.length).toBe(before + 1);
    expect(lastFacts(client)?.hpkePublicKey).toBe(ehbp.publicKeyHex);
  });

  it("closes with nothing to release, and a sealed exchange in flight completes", async () => {
    const client = await createEnclaveHTTPClient(
      "enclave.example",
      AUTHORIZED,
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` } },
      { verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex })), documentFetch: documents().fetch });
    const inFlight = client.fetch(`${ehbp.origin}/echo`, { method: "POST", body: "still going" });
    await client.close();
    expect((await (await inFlight).json()).text).toBe("still going");
    await expect(client.fetch(`${ehbp.origin}/echo`, { method: "POST", body: "x" })).rejects.toThrow(/client is closed/);
    expect(lastFacts(client)?.hpkePublicKey).toBe(ehbp.publicKeyHex);
  });

  it("runs the caller's verification check and backs an OpenAI client on the proxy base URL", async () => {
    const seen: string[] = [];
    const docs = documents();
    const ai = await openAIOver(createEnclaveHTTPClient("enclave.example", AUTHORIZED, { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` }, verificationCheck: (v) => void seen.push(v.hpkePublicKey!) }, { verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex })), documentFetch: docs.fetch }), { apiKey: "k" });
    expect(seen).toEqual([ehbp.publicKeyHex]);
    expect(ai.baseURL).toBe(`${ehbp.origin}/v1/`);
    expect(ai.httpClient).toBeInstanceOf(EnclaveHTTPClient);
    const completion = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(completion.choices[0]!.message.content).toBe("sealed");
    const last = ehbp.seen[ehbp.seen.length - 1]!;
    expect(last.path).toBe("/v1/chat/completions");
    expect(last.sealed).toBe(true);
    expect(last.headers["x-tinfoil-enclave-url"]).toBe("https://enclave.example");
    expect(last.headers.authorization).toBe("Bearer k");
  });
});
