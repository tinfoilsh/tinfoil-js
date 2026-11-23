/**
 * The AI SDK provider on local servers: the credential rules and option
 * checks before any network I/O, requests from `generateText` reaching the
 * server through the attested fetch with the credential and the cache
 * secret, the enclave route sealing bodies, `streamText` observing chunks
 * before the server ends the stream, abort, and the AI SDK's tool-calling
 * and structured-output paths parsing what the server answers.
 */
import { generateObject, generateText, NoObjectGeneratedError, Output, streamText, tool } from "ai";
import { PROTOCOL } from "ehbp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { createTinfoil, createTinfoilProvider, type TinfoilProviderOptions, type TinfoilProviderSeams } from "../src/internal/ai-sdk.js";
import { EnclaveHTTPClient } from "../src/enclave-client.js";
import { ConfigurationError } from "../src/errors.js";
import type { RuntimeGlobals } from "../src/internal/platform.js";
import { createTinfoilClient } from "../src/openai-client.js";
import type { Fetch, Transport } from "../src/options.js";
import { RouterHTTPClient } from "../src/router-client.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type VerificationReport, type VerifiedFacts, type Verifier } from "../../verifier/src/index.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";
import { recordingFetch } from "./helpers/network.js";
import { paced, startTlsServer, TEST_CERT, TEST_PIN, type Seen, type TlsServer } from "./helpers/tls-server.js";
import { lastFacts, verifiedReport } from "./helpers/report.js";

const MODEL = "test-model";
const ROUTER_REPO = "tinfoilsh/confidential-model-router";

let tls: TlsServer;
let ehbp: EhbpServer;
let sseEnded = false;

function verifier(keys: { tls?: string; hpke?: string }): Verifier {
  return {
    checkPinVerifiability: ({ repo = "" }: { repo?: string }) => {
      if (repo === "") throw new UsageError("repo required");
    },
    verifyV3At: async () => {
      const material = [
        ...(keys.tls === undefined ? [] : [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: keys.tls }]),
        ...(keys.hpke === undefined ? [] : [{ id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: keys.hpke }]),
      ];
      return verifiedReport({
        cryptoMaterial: material.map((m) => ({ ...m })),
        tlsPublicKeyFP: keys.tls,
        hpkePublicKey: keys.hpke,
        codeDigest: "11".repeat(32),
        freshnessExpiresAt: new Date(Date.now() + 60_000),
      });
    },
  } as unknown as Verifier;
}

/** Seams that discover `routers`, count document fetches, and resolve the cache secret without touching the environment. */
function seams(routers: string[]): TinfoilProviderSeams & { documentFetches: number } {
  const state = { documentFetches: 0 };
  const documentFetch: Fetch = async () => {
    state.documentFetches++;
    return new Response(new Uint8Array([1]));
  };
  return Object.assign(state, {
    routersFetch: (async () => new Response(JSON.stringify(routers))) as Fetch,
    documentFetch,
    sleep: async () => {},
    tls: { ca: TEST_CERT },
    resolveSecret: (explicit: string | undefined) => explicit || "resolved-secret",
  });
}

const completion = (message: Record<string, unknown>, finishReason = "stop"): string =>
  JSON.stringify({ id: "c", object: "chat.completion", created: 1, model: MODEL, choices: [{ index: 0, message: { role: "assistant", ...message }, finish_reason: finishReason }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });

const sseChunk = (delta: Record<string, unknown>, finishReason: string | null = null): string =>
  `data: ${JSON.stringify({ id: "c", object: "chat.completion.chunk", created: 1, model: MODEL, choices: [{ index: 0, delta, finish_reason: finishReason }] })}\n\n`;

/** Answers as a model would: a tool call when tools are offered, JSON when a schema is requested, a stream when asked, text otherwise. */
function answer(seen: Pick<Seen, "path" | "body">): { headers: Record<string, string>; body: string | AsyncIterable<Uint8Array> } {
  if (!seen.path.endsWith("/chat/completions")) return { headers: { "content-type": "text/plain" }, body: "not a completion" };
  const request = JSON.parse(new TextDecoder().decode(seen.body)) as Record<string, unknown>;
  if (request.stream === true) {
    sseEnded = false;
    const text = (request.response_format as { type?: string } | undefined)?.type === "json_schema" ? JSON.stringify({ name: "Alice", age: 30 }) : "one two three";
    const chunks = text.split(" ").map((word, i) => sseChunk({ content: `${i === 0 ? "" : " "}${word}` }));
    return { headers: { "content-type": "text/event-stream" }, body: paced([...chunks, sseChunk({}, "stop"), "data: [DONE]\n\n"], 60, () => (sseEnded = true)) };
  }
  const json = { "content-type": "application/json" };
  if (Array.isArray(request.tools) && request.tools.length > 0) {
    return { headers: json, body: completion({ content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "weather", arguments: JSON.stringify({ location: "San Francisco" }) } }] }, "tool_calls") };
  }
  const format = request.response_format as { type?: string } | undefined;
  if (format?.type === "json_schema" || format?.type === "json_object") {
    const invalid = (request.messages as { content?: string }[]).some((m) => typeof m.content === "string" && m.content.includes("INVALID"));
    return { headers: json, body: completion({ content: JSON.stringify(invalid ? { name: 7 } : { name: "Alice", age: 30 }) }) };
  }
  return { headers: json, body: completion({ content: "pong" }) };
}

const lastRequest = (server: { seen: Seen[] }): { seen: Seen; body: Record<string, unknown> } => {
  const seen = server.seen[server.seen.length - 1]!;
  return { seen, body: JSON.parse(new TextDecoder().decode(seen.body)) as Record<string, unknown> };
};

beforeAll(async () => {
  tls = await startTlsServer(answer);
  ehbp = await startEhbpServer(answer);
});

afterAll(async () => {
  await Promise.all([tls.close(), ehbp.close()]);
});

describe("createTinfoil's option checks", () => {
  it("requires exactly one credential and checks the client's options before fetching anything", async () => {
    // Assigned rather than spread, so that the fetch counter stays the one the seams increment.
    const s = Object.assign(seams([tls.host]), { verifier: verifier({ tls: TEST_PIN }) });
    const network = recordingFetch((input, init) => fetch(input, init));
    const cases: [TinfoilProviderOptions, RegExp][] = [
      [{}, /credential is required/],
      [{ apiKey: "" }, /credential is required/],
      [{ apiKey: "k", bearerToken: "t" }, /not both/],
      [{ apiKey: "k", enclave: { host: "", trust: { kind: "repoPin", repo: ROUTER_REPO } } }, /host is required/],
      [{ transport: { kind: "ehbp", proxyURL: "http://proxy.example/" }, apiKey: "k" }, /HTTP is allowed only for localhost/],
      [{ transport: { kind: "quic" } as unknown as Transport, apiKey: "k" }, /transport must have kind/],
      [{ apiKey: "k", apiPath: "v1/" }, /invalid API path/],
      [{ apiKey: "k", enclave: null } as unknown as TinfoilProviderOptions, /enclave must be an object/],
      [{ apiKey: "k", enclave: { host: "enclave.example", trust: { kind: "repoPin", repo: ROUTER_REPO } }, userCacheSecret: "s" } as unknown as TinfoilProviderOptions, /userCacheSecret is the router's option/],
      [{ apiKey: "k", enclave: { host: "enclave.example", trust: { kind: "projectPin", project: "org/project", registryIDs: [] } } }, /registryIDs must not be empty/],
      [{ apiKey: "k", enclave: { host: "enclave.example", repo: ROUTER_REPO } as never }, /trust is required/],
    ];
    for (const [options, message] of cases) {
      const failure = createTinfoilProvider(options, s);
      await expect(failure, JSON.stringify(options)).rejects.toBeInstanceOf(ConfigurationError);
      await expect(failure).rejects.toThrow(message);
    }
    expect(s.documentFetches).toBe(0);
    expect(tls.seen).toHaveLength(0);
    expect(network.seen).toHaveLength(0);
  });

  it("refuses an API key where the runtime isn't a server, such as a worker, before fetching anything", async () => {
    const worker = { self: {} } as unknown as RuntimeGlobals;
    const s = seams([tls.host]);
    const failure = createTinfoilProvider({ apiKey: "long-lived" }, { verifier: verifier({ tls: TEST_PIN }), ...s, globals: worker });
    await expect(failure).rejects.toBeInstanceOf(ConfigurationError);
    await expect(failure).rejects.toThrow(/bearerToken/);
    expect(s.documentFetches).toBe(0);
    // The worker's transport check runs through the same globals: TLS is refused there.
    const pinned = createTinfoilProvider({ transport: { kind: "tls" }, bearerToken: "t" }, { verifier: verifier({ tls: TEST_PIN }), ...s, globals: worker });
    await expect(pinned).rejects.toBeInstanceOf(ConfigurationError);
    await expect(pinned).rejects.toThrow(/browsers don't expose/);
    expect(s.documentFetches).toBe(0);
    // A bearer token over sealed bodies is accepted there; the server runtime accepts either credential and either mode.
    const sealed = await createTinfoilProvider(
      { bearerToken: "t", enclave: { host: "enclave.example", trust: { kind: "eitherPin", repo: "tinfoilsh/repo", project: "tinfoilsh/project" } }, transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` } },
      { verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }), ...seams([]), globals: worker });
    expect(sealed.httpClient).toBeInstanceOf(EnclaveHTTPClient);
    expect((sealed.httpClient as EnclaveHTTPClient).trust).toEqual({ kind: "eitherPin", repo: "tinfoilsh/repo", project: "tinfoilsh/project" });
    const node = { process: { versions: { node: "22.0.0" } } } as RuntimeGlobals;
    await expect(createTinfoilProvider({ transport: { kind: "tls" }, apiKey: "k" }, { verifier: verifier({ tls: TEST_PIN }), ...s, globals: node })).resolves.toBeDefined();
  });

  it("refuses an API key outside a server with the same error as the OpenAI client", async () => {
    const worker = { self: {} } as unknown as RuntimeGlobals;
    const s = seams([tls.host]);
    const rejection = (p: Promise<unknown>): Promise<Error> => p.then(() => Promise.reject(new Error("resolved")), (e: unknown) => e as Error);
    const provider = await rejection(createTinfoilProvider({ apiKey: "k" }, { ...s, globals: worker }));
    const client = await rejection(createTinfoilClient({ apiKey: "k" }, { ...s, globals: worker }));
    expect(provider).toBeInstanceOf(ConfigurationError);
    expect(client).toBeInstanceOf(ConfigurationError);
    expect(client.message).toBe(provider.message);
    expect(s.documentFetches).toBe(0);
  });

  it("is reachable from the public surface with the same checks", async () => {
    await expect(createTinfoil({})).rejects.toBeInstanceOf(ConfigurationError);
  });
});

describe("the provider over the discovered router", () => {
  let s: ReturnType<typeof seams>;
  let tinfoil: Awaited<ReturnType<typeof createTinfoilProvider>>;
  const reported: string[] = [];

  beforeAll(async () => {
    s = seams([tls.host]);
    tinfoil = await createTinfoilProvider(
      { transport: { kind: "tls" }, apiKey: "secret-key", headers: { "x-app": "demo" }, onVerification: (host) => void reported.push(host) },
      { ...s, verifier: verifier({ tls: TEST_PIN }) },
    );
  });

  it("is bound to the verified router and exposes it", () => {
    const client = tinfoil.httpClient;
    expect(client).toBeInstanceOf(RouterHTTPClient);
    expect(client.enclave).toBe(tls.host);
    expect(lastFacts(client)?.tlsPublicKeyFP).toBe(TEST_PIN);
    expect(reported).toEqual([tls.host]);
    expect(Object.getOwnPropertyDescriptor(tinfoil, "httpClient")?.writable).toBe(false);
  });

  it("sends generateText through the attested fetch with the credential, the headers and the cache secret", async () => {
    const { text, finishReason } = await generateText({ model: tinfoil(MODEL), prompt: "Say pong", maxRetries: 0 });
    expect(text).toBe("pong");
    expect(finishReason).toBe("stop");
    const { seen, body } = lastRequest(tls);
    expect(seen.path).toBe("/v1/chat/completions");
    expect(seen.headers["authorization"]).toBe("Bearer secret-key");
    expect(seen.headers["x-app"]).toBe("demo");
    expect(body.model).toBe(MODEL);
    expect(body.user_cache_secret).toBe("resolved-secret");
  });

  it("streams chunks as the server produces them, before the stream ends", async () => {
    const result = streamText({ model: tinfoil(MODEL), prompt: "Count", maxRetries: 0 });
    const deltas: string[] = [];
    let endedAtFirstDelta: boolean | undefined;
    for await (const delta of result.textStream) {
      if (endedAtFirstDelta === undefined) endedAtFirstDelta = sseEnded;
      deltas.push(delta);
    }
    expect(endedAtFirstDelta).toBe(false);
    expect(deltas.join("")).toBe("one two three");
    expect(await result.finishReason).toBe("stop");
    expect(lastRequest(tls).body.stream).toBe(true);
  });

  it("stops a stream when the caller aborts", async () => {
    const controller = new AbortController();
    const result = streamText({ model: tinfoil(MODEL), prompt: "Count", maxRetries: 0, abortSignal: controller.signal });
    let deltas = 0;
    await expect(
      (async () => {
        for await (const delta of result.textStream) {
          void delta;
          deltas++;
          controller.abort();
        }
      })(),
    ).rejects.toThrow(/abort/i);
    expect(deltas).toBe(1);
  });

  it("lets the AI SDK call tools and parse structured output through the attested fetch", async () => {
    const { toolCalls } = await generateText({
      model: tinfoil(MODEL),
      prompt: "What is the weather in San Francisco?",
      maxRetries: 0,
      tools: {
        weather: tool({
          description: "Get weather for a location",
          inputSchema: z.object({ location: z.string() }),
          execute: async ({ location }) => ({ temperature: 72, location }),
        }),
      },
    });
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0]!.toolName).toBe("weather");
    expect(toolCalls[0]!.input).toEqual({ location: "San Francisco" });

    const person = z.object({ name: z.string(), age: z.number() });
    const { object } = await generateObject({ model: tinfoil(MODEL), schema: person, prompt: "Generate a person.", maxRetries: 0 });
    expect(object).toEqual({ name: "Alice", age: 30 });
    expect((lastRequest(tls).body.response_format as { type: string }).type).toBe("json_schema");

    const { output } = await generateText({ model: tinfoil(MODEL), output: Output.object({ schema: person }), prompt: "Generate a person.", maxRetries: 0 });
    expect(output).toEqual({ name: "Alice", age: 30 });

    await expect(generateText({ model: tinfoil(MODEL), output: Output.object({ schema: person }), prompt: "INVALID", maxRetries: 0 })).rejects.toBeInstanceOf(NoObjectGeneratedError);
  });
});

describe("the provider over one enclave", () => {
  it("seals bodies to the enclave's key through a proxy and exposes the enclave client", async () => {
    const s = seams([]);
    const tinfoil = await createTinfoilProvider(
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` }, bearerToken: "short-lived", enclave: { host: "enclave.example", trust: { kind: "repoPin", repo: "tinfoilsh/repo" } } },
      { ...s, verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) });
    const client = tinfoil.httpClient;
    expect(client).toBeInstanceOf(EnclaveHTTPClient);
    expect(client.enclave).toBe("enclave.example");
    expect(lastFacts(client)?.hpkePublicKey).toBe(ehbp.publicKeyHex);

    const { text } = await generateText({ model: tinfoil(MODEL), prompt: "Say pong", maxRetries: 0 });
    expect(text).toBe("pong");
    const seen = ehbp.seen[ehbp.seen.length - 1]!;
    expect(seen.sealed).toBe(true);
    expect(seen.headers["authorization"]).toBe("Bearer short-lived");
    expect(seen.headers["x-tinfoil-enclave-url"]).toBe("https://enclave.example");
    // An enclave client never adds a cache secret.
    expect(JSON.parse(new TextDecoder().decode(seen.body))).not.toHaveProperty("user_cache_secret");
  });
});

describe("the provider's fetch option", () => {
  it("sends sealed requests through the fetch option, while discovery keeps its own fetches", async () => {
    const network = recordingFetch((input, init) => fetch(input, init));
    const s = seams(["router.example"]);
    const tinfoil = await createTinfoilProvider(
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/`, fetch: network.fetch }, apiKey: "secret-key" },
      { ...s, verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) });
    expect(tinfoil.httpClient).toBeInstanceOf(RouterHTTPClient);
    expect(s.documentFetches).toBe(1);
    expect(network.seen).toHaveLength(0);

    const { text } = await generateText({ model: tinfoil(MODEL), prompt: "Say pong", maxRetries: 0 });
    expect(text).toBe("pong");
    expect(network.seen).toHaveLength(1);
    const sealed = network.seen[0]!;
    expect(sealed.url).toBe(`${ehbp.origin}/v1/chat/completions`);
    expect(sealed.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER)).toBe(true);
    expect(sealed.headers.get("x-tinfoil-enclave-url")).toBe("https://router.example");
    expect(sealed.headers.get("authorization")).toBe("Bearer secret-key");
    expect(sealed.body).not.toContain("Say pong");
    expect(sealed.body).not.toContain("resolved-secret");
    // The server opened what the network carried: the prompt and the secret spliced in before sealing.
    const seen = ehbp.seen[ehbp.seen.length - 1]!;
    expect(seen.sealed).toBe(true);
    expect(JSON.parse(new TextDecoder().decode(seen.body))).toHaveProperty("user_cache_secret", "resolved-secret");
  });
});
