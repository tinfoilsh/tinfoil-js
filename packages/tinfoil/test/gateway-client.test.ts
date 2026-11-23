/**
 * The gateway clients end to end against the local EHBP server standing in
 * for the gateway: option checks before any network I/O, the catalog fetched
 * before the factory returns, requests sealed to the verified replica with
 * the cache scope applied, the replica listing, and the OpenAI client over it.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, NetworkError } from "../src/errors.js";
import { createGatewayHTTPClient, DEFAULT_GATEWAY_URL, fetchCatalog, GatewayHTTPClient, type GatewayClientSeams } from "../src/gateway-client.js";
import { OpenAIClient } from "../src/openai-client.js";
import type { Catalog, Fetch, GatewayOptions } from "../src/options.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verifier } from "../../verifier/src/index.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";
import { recordingFetch } from "./helpers/network.js";
import { expectWithOptionsRefusesTransportOptions } from "./helpers/transport-options.js";
import { openAIOver } from "./helpers/openai.js";
import { verifiedReport } from "./helpers/report.js";

const GATEWAY_URL = "https://gateway.example/v1/";
const CATALOG = { "test-model": { repo: "tinfoilsh/test", hosts: ["replica-a.example", "replica-b.example"] }, other: { repo: "tinfoilsh/other", hosts: ["o.example"] } };
let gateway: EhbpServer;

function verifier(hpke: string): Verifier {
  return {
    checkPinVerifiability: ({ repo = "" }: { repo?: string }) => {
      if (repo === "") throw new UsageError("repo required");
    },
    verifyV3At: async () => {
      const material = [
        { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) },
        { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke },
      ];
      return verifiedReport({
        cryptoMaterial: material.map((m) => ({ ...m })),
        tlsPublicKeyFP: "ab".repeat(32),
        hpkePublicKey: hpke,
        codeDigest: "11".repeat(32),
        freshnessExpiresAt: new Date(Date.now() + 60_000),
      });
    },
  } as unknown as Verifier;
}

/** A fetch that sends requests addressed to the gateway's name to the local server standing in for it. */
function toLocal(calls?: string[]): Fetch {
  return (input, init) => {
    const request = new Request(input, init);
    calls?.push(request.url);
    const url = new URL(request.url);
    const local = new URL(gateway.origin);
    url.protocol = local.protocol;
    url.host = local.host;
    return fetch(new Request(url, request));
  };
}

function seams(extra: Partial<GatewayClientSeams> = {}): GatewayClientSeams & { calls: string[] } {
  const calls: string[] = [];
  return { calls, catalogFetch: toLocal(calls), documentFetch: toLocal(calls), sleep: async () => {}, ehbp: { fetch: toLocal() }, resolveSecret: (s) => s || "resolved-secret", ...extra };
}

function completion(content: string): unknown {
  return { id: "c", object: "chat.completion", created: 1, model: "test", choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }] };
}

beforeAll(async () => {
  gateway = await startEhbpServer((seen) => {
    if (seen.path === "/catalog") return { headers: { "content-type": "application/json" }, body: JSON.stringify(CATALOG) };
    if (seen.path.startsWith("/.well-known/tinfoil-attestation")) return { headers: { "content-type": "application/octet-stream" }, body: new Uint8Array([1]) };
    if (seen.path === "/v1/chat/completions" && seen.headers["x-raw"] === undefined) {
      return { headers: { "content-type": "application/json" }, body: JSON.stringify(completion(seen.sealed ? "sealed" : "plain")) };
    }
    return { headers: { "content-type": "text/plain" }, body: new TextDecoder().decode(seen.body) };
  });
});

afterAll(async () => {
  await gateway.close();
});

describe("GatewayHTTPClient.create", () => {
  it("checks its options before fetching anything", async () => {
    const s = seams();
    const v = verifier(gateway.publicKeyHex);
    const cases: GatewayOptions[] = [
      { url: "http://gateway.example/v1/" },
      { url: "not a url" },
      { url: "ftp://gateway.example/v1/" },
      { url: "https://user:pw@gateway.example/v1/" },
      { url: "https://gateway.example/v1/?key=1" },
      { url: "https://gateway.example/v1/#frag" },
      { pinnedModelsOnly: true },
      { modelPins: new Map([["m", { repo: "other/m" }]]) },
    ];
    for (const options of cases) {
      await expect(createGatewayHTTPClient(options, { ...s, verifier: v }), JSON.stringify(options.url)).rejects.toBeInstanceOf(ConfigurationError);
    }
    expect(s.calls).toEqual([]);
    expect(DEFAULT_GATEWAY_URL).toBe("https://inference-gateway.tinfoil.sh/v1/");
  });

  it("fetches the catalog before returning and reports an unreachable gateway as a network error", async () => {
    const unreachable = seams({
      catalogFetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    await expect(createGatewayHTTPClient({ url: GATEWAY_URL }, { ...unreachable, verifier: verifier(gateway.publicKeyHex) })).rejects.toBeInstanceOf(NetworkError);
    const s = seams();
    const client = await createGatewayHTTPClient({ url: GATEWAY_URL }, { ...s, verifier: verifier(gateway.publicKeyHex) });
    expect(s.calls).toEqual(["https://gateway.example/catalog"]);
    expect(Object.keys(client)).toEqual(["fetch", "baseURL"]);
    expect(() => ((client as { baseURL: string }).baseURL = "https://evil.example/")).toThrow(TypeError);
    expect(client.baseURL).toBe(GATEWAY_URL);
    expect(await client.models()).toEqual(["other", "test-model"]);
    expect(client.lastVerification()).toEqual([]);
    const supplied = await createGatewayHTTPClient({ url: GATEWAY_URL, catalog: () => new Map() as Catalog }, { ...seams(), verifier: verifier(gateway.publicKeyHex) });
    expect(await supplied.models()).toEqual([]);
    const bare = await createGatewayHTTPClient({ url: "https://gateway.example/v1" }, { ...seams(), verifier: verifier(gateway.publicKeyHex) });
    expect(bare.baseURL).toBe(GATEWAY_URL);
    const padded = await createGatewayHTTPClient({ url: "  https://gateway.example/v1  " }, { ...seams(), verifier: verifier(gateway.publicKeyHex) });
    expect(padded.baseURL).toBe(GATEWAY_URL);
    await expect(bare.fetch("https://other.example/v1/models")).rejects.toThrow(/client is bound/);
  });
});

describe("GatewayHTTPClient.create when no cache secret can be generated", () => {
  it("fails with the error unchanged before any network I/O", async () => {
    const failure = new Error("no secure randomness");
    const s = seams({
      resolveSecret: () => {
        throw failure;
      },
    });
    await expect(createGatewayHTTPClient({ url: GATEWAY_URL }, { ...s, verifier: verifier(gateway.publicKeyHex) })).rejects.toBe(failure);
    expect(s.calls).toEqual([]);
  });
});

describe("GatewayHTTPClient", () => {
  let client: GatewayHTTPClient;
  let s: ReturnType<typeof seams>;

  beforeAll(async () => {
    s = seams();
    client = await createGatewayHTTPClient({ url: GATEWAY_URL, modelPins: new Map([["test-model", { repo: "tinfoilsh/test" }]]) }, { ...s, verifier: verifier(gateway.publicKeyHex) });
  });

  it("verifies a replica through the gateway on first use and seals the request to it, with the cache scope applied", async () => {
    const body = '{"model":"test-model","messages":[{"role":"user","content":"hi"}],"seed":9223372036854775807}';
    const res = await client.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body, headers: { "content-type": "application/json", "x-raw": "1", authorization: "Bearer k" } });
    expect(res.status).toBe(200);
    const received = await res.text();
    expect(received.startsWith(body.slice(0, -1))).toBe(true);
    expect(JSON.parse(received)).toMatchObject({ model: "test-model", seed: expect.anything(), cache_salt: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) });
    expect(received).not.toContain("user_cache_secret");
    const attestations = s.calls.filter((c) => c.includes("tinfoil-attestation"));
    expect(attestations).toHaveLength(1);
    expect(new URL(attestations[0]!).searchParams.get("enclave")).toMatch(/^replica-[ab]\.example$/);
    const last = gateway.seen[gateway.seen.length - 1]!;
    expect(last.sealed).toBe(true);
    expect(last.headers["x-tinfoil-enclave-url"]).toMatch(/^https:\/\/replica-[ab]\.example$/);
    expect(last.headers["x-tinfoil-seal"]).toMatch(/^replica-[ab]\.example$/);
    expect(last.headers["x-tinfoil-model"]).toBe("test-model");
    expect(last.headers["x-tinfoil-cache-prefix"]).toMatch(/^[0-9a-f]{64}$/);
    const current = client.lastVerification();
    expect(current).toHaveLength(1);
    expect(current[0]).toMatchObject({ reference: "tinfoilsh/test", pinnedModel: "test-model", models: ["test-model"] });
    expect(current[0]!.report!.verifiedFacts!.hpkePublicKey).toBe(gateway.publicKeyHex);
    expect((await client.ensureVerified("test-model")).verifiedFacts?.hpkePublicKey).toBe(gateway.publicKeyHex);
  });

  it("stops a call waiting when its signal aborts, rejecting with the signal's own reason", async () => {
    const reason = new Error("gave up");
    const signal = AbortSignal.abort(reason);
    const before = s.calls.length;
    await expect(client.models({ signal })).rejects.toBe(reason);
    await expect(client.ensureVerified("test-model", { signal })).rejects.toBe(reason);
    await expect(fetchCatalog("gateway.example", { signal })).rejects.toBe(reason);
    expect(s.calls).toHaveLength(before);
  });

  it("closes: refuses further use, keeps the replicas' last verifications, and closes again without effect", async () => {
    const own = seams();
    const c = await createGatewayHTTPClient({ url: GATEWAY_URL }, { ...own, verifier: verifier(gateway.publicKeyHex) });
    await c.ensureVerified("test-model");
    const fetched = own.calls.length;
    await c.close();
    await c.close();
    expect(c.lastVerification()).toHaveLength(1);
    await expect(c.models()).rejects.toThrow(/client is closed/);
    await expect(c.ensureVerified("test-model")).rejects.toBeInstanceOf(ConfigurationError);
    await expect(c.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body: '{"model":"test-model"}', headers: { "content-type": "application/json" } })).rejects.toThrow(/client is closed/);
    expect(own.calls).toHaveLength(fetched);
  });

  it("refuses other origins, upgrades, and models the policy doesn't serve", async () => {
    await expect(client.fetch("https://other.example/v1/models")).rejects.toThrow(/client is bound/);
    await expect(client.fetch(`${GATEWAY_URL}realtime`, { headers: { upgrade: "websocket" } })).rejects.toThrow(/protocol upgrade/);
    await expect(client.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body: '{"model":"unknown"}', headers: { "content-type": "application/json" } })).rejects.toBeInstanceOf(ConfigurationError);
    await expect(client.fetch(`${GATEWAY_URL}models`)).rejects.toThrow(/model "" has no valid/);
    const swapped = await createGatewayHTTPClient(
      { url: GATEWAY_URL, modelPins: new Map([["other", { repo: "tinfoilsh/pinned-elsewhere" }]]) },
      { ...seams(), verifier: verifier(gateway.publicKeyHex) });
    await expect(swapped.ensureVerified("other")).rejects.toBeInstanceOf(AttestationError);
  });

  it("falls over to the replica the caller's check accepts", async () => {
    const checked: string[] = [];
    const c = await createGatewayHTTPClient(
      { url: GATEWAY_URL, verificationCheck: (v) => {
          checked.push(v.hpkePublicKey!);
          if (checked.length === 1) throw new Error("not this replica");
        } },
      { ...seams(), verifier: verifier(gateway.publicKeyHex) });
    const res = await c.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body: '{"model":"test-model"}', headers: { "content-type": "application/json", "x-raw": "1" } });
    expect(res.status).toBe(200);
    expect(checked).toHaveLength(2);
    // Both replicas were tried: the rejected one keeps its check's error, and the one sealed to its report.
    const attempts = c.lastVerification();
    expect(attempts).toHaveLength(2);
    const passed = attempts.filter((r) => r.report !== undefined);
    expect(passed).toHaveLength(1);
    expect(attempts.find((r) => r.error !== undefined)?.error?.message).toMatch(/not this replica/);
    expect(gateway.seen[gateway.seen.length - 1]!.headers["x-tinfoil-seal"]).toBe(passed[0]!.host);
  });

  it("falls over to a replica that verifies and runs the caller's check", async () => {
    const checked: string[] = [];
    const failing = seams({
      documentFetch: async (input, init) => {
        const enclave = new URL(String(input)).searchParams.get("enclave");
        return enclave === "replica-a.example" ? new Response("no", { status: 503 }) : toLocal()(input, init);
      },
    });
    const c = await createGatewayHTTPClient({ url: GATEWAY_URL, verificationCheck: (v) => void checked.push(v.hpkePublicKey!) }, { ...failing, verifier: verifier(gateway.publicKeyHex) });
    const res = await c.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body: '{"model":"test-model"}', headers: { "content-type": "application/json", "x-raw": "1" } });
    expect(res.status).toBe(200);
    expect(c.lastVerification().filter((r) => r.report !== undefined).map((r) => r.host)).toEqual(["replica-b.example"]);
    // replica-a, if it was tried first, keeps the failure of its attestation fetch.
    for (const failed of c.lastVerification().filter((r) => r.report === undefined)) {
      expect(failed.host).toBe("replica-a.example");
      expect(failed.error).toBeInstanceOf(NetworkError);
    }
    expect(checked).toEqual([gateway.publicKeyHex]);
    expect(() => new (GatewayHTTPClient as any)(Symbol("x"))).toThrow(ConfigurationError);
  });
});

describe("GatewayHTTPClient with a network fetch", () => {
  it("sends sealed requests through the fetch option, while the catalog and attestation documents keep their own fetches", async () => {
    const network = recordingFetch(toLocal());
    const s = seams({ ehbp: undefined });
    const client = await createGatewayHTTPClient({ url: GATEWAY_URL, fetch: network.fetch }, { ...s, verifier: verifier(gateway.publicKeyHex) });
    expect(s.calls).toEqual(["https://gateway.example/catalog"]);
    expect(network.seen).toHaveLength(0);

    const res = await client.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body: '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}', headers: { "content-type": "application/json", "x-raw": "1", authorization: "Bearer k" } });
    expect(JSON.parse(await res.text())).toMatchObject({ model: "test-model", cache_salt: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) });
    expect(s.calls.filter((c) => c.includes("tinfoil-attestation"))).toHaveLength(1);
    expect(network.seen).toHaveLength(1);
    const sealed = network.seen[0]!;
    expect(sealed.url).toBe(`${GATEWAY_URL}chat/completions`);
    expect(sealed.headers.get("x-tinfoil-model")).toBe("test-model");
    expect(sealed.headers.get("authorization")).toBe("Bearer k");
    expect(sealed.body).not.toContain("messages");
    expect(gateway.seen[gateway.seen.length - 1]!.sealed).toBe(true);
  });
});

describe("OpenAIClient<GatewayHTTPClient>", () => {
  it("backs an OpenAI client on the gateway URL with the option's secret", async () => {
    const ai = await openAIOver(createGatewayHTTPClient({ url: GATEWAY_URL, userCacheSecret: "option-secret" }, { ...seams({ resolveSecret: undefined }), verifier: verifier(gateway.publicKeyHex) }), { apiKey: "k" });
    expect(ai).toBeInstanceOf(OpenAIClient);
    expect(ai.baseURL).toBe(GATEWAY_URL);
    expect(ai.httpClient).toBeInstanceOf(GatewayHTTPClient);
    const reply = await ai.chat.completions.create({ model: "test-model", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("sealed");
    const last = gateway.seen[gateway.seen.length - 1]!;
    expect(last.path).toBe("/v1/chat/completions");
    expect(last.headers.authorization).toBe("Bearer k");
    const sent = JSON.parse(new TextDecoder().decode(last.body)) as Record<string, unknown>;
    expect(sent.cache_salt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(sent.user_cache_secret).toBeUndefined();
    expect(() => new OpenAIClient(Symbol("x") as never)).toThrow(ConfigurationError);
    expectWithOptionsRefusesTransportOptions(ai);
    // The gateway's URL already carries the API path, so an API path of the caller's own is refused.
    expect(() => new OpenAIClient(ai.httpClient, { apiPath: "/v1/" }, { apiKey: "k" })).toThrow(/a gateway client's URL already carries the API path/);
    expect(new OpenAIClient(ai.httpClient, { apiPath: "" }, { apiKey: "k" }).baseURL).toBe(GATEWAY_URL);
  });
});
