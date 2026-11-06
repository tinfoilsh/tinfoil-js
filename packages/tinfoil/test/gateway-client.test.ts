/**
 * The gateway clients end to end against the local EHBP server standing in
 * for the gateway: option checks before any network I/O, the catalog fetched
 * before the factory returns, requests sealed to the verified replica with
 * the cache scope applied, the replica listing, and the OpenAI client over it.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, NetworkError } from "../src/errors.js";
import { createGatewayHTTPClient, DEFAULT_GATEWAY_URL, fetchCatalog, GatewayHTTPClient, type GatewayClientSeams } from "../src/gateway-client.js";
import { createGatewayOpenAIClient, GatewayOpenAIClient } from "../src/openai-client.js";
import type { Catalog, Fetch, GatewayOptions } from "../src/options.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verification, type Verifier } from "../../verifier/src/index.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";

const GATEWAY_URL = "https://gateway.example/v1/";
const CATALOG = { "test-model": { repo: "tinfoilsh/test", hosts: ["replica-a.example", "replica-b.example"] }, other: { repo: "tinfoilsh/other", hosts: ["o.example"] } };
let gateway: EhbpServer;

function verifier(hpke: string, authorizes = false): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo === "") throw new UsageError("repo required");
    },
    callerAuthorizesConfig: authorizes,
    verifyV3At: async () => {
      const material = [
        { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) },
        { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke },
      ];
      return {
        cryptoMaterial: material.map((m) => ({ ...m })),
        tlsPublicKeyFP: "ab".repeat(32),
        hpkePublicKey: hpke,
        codeDigest: "11".repeat(32),
        freshnessExpiresAt: new Date(Date.now() + 60_000),
      } as unknown as Verification;
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
  return { calls, catalogFetch: toLocal(calls), documentFetch: toLocal(calls), sleep: async () => {}, ehbp: { fetch: toLocal() }, resolveSecret: async (s) => s || "resolved-secret", ...extra };
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
      { verifier: v, url: "http://gateway.example/v1/" },
      { verifier: v, url: "not a url" },
      { verifier: v, url: "ftp://gateway.example/v1/" },
      { verifier: v, url: "https://user:pw@gateway.example/v1/" },
      { verifier: v, url: "https://gateway.example/v1/?key=1" },
      { verifier: v, url: "https://gateway.example/v1/#frag" },
      { verifier: v, pinnedModelsOnly: true },
      { verifier: verifier(gateway.publicKeyHex, true) },
      { verifier: v, modelPins: new Map([["m", { repo: "other/m" }]]) },
    ];
    for (const options of cases) {
      await expect(createGatewayHTTPClient(options, s), JSON.stringify(options.url)).rejects.toBeInstanceOf(ConfigurationError);
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
    await expect(createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL }, unreachable)).rejects.toBeInstanceOf(NetworkError);
    const s = seams();
    const client = await createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL }, s);
    expect(s.calls).toEqual(["https://gateway.example/catalog"]);
    expect(Object.keys(client)).toEqual(["fetch", "baseURL"]);
    expect(() => ((client as { baseURL: string }).baseURL = "https://evil.example/")).toThrow(TypeError);
    expect(client.baseURL).toBe(GATEWAY_URL);
    expect(await client.models()).toEqual(["other", "test-model"]);
    expect(client.current).toEqual([]);
    const supplied = await createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL, catalog: () => new Map() as Catalog }, seams());
    expect(await supplied.models()).toEqual([]);
    const bare = await createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: "https://gateway.example/v1" }, seams());
    expect(bare.baseURL).toBe(GATEWAY_URL);
    const padded = await createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: "  https://gateway.example/v1  " }, seams());
    expect(padded.baseURL).toBe(GATEWAY_URL);
    await expect(bare.fetch("https://other.example/v1/models")).rejects.toThrow(/client is bound/);
  });
});

describe("GatewayHTTPClient", () => {
  let client: GatewayHTTPClient;
  let s: ReturnType<typeof seams>;

  beforeAll(async () => {
    s = seams();
    client = await createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL, modelPins: new Map([["test-model", { repo: "tinfoilsh/test" }]]) }, s);
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
    const current = client.current;
    expect(current).toHaveLength(1);
    expect(current[0]).toMatchObject({ reference: "tinfoilsh/test", pinnedModel: "test-model", models: ["test-model"] });
    expect(current[0]!.verification.hpkePublicKey).toBe(gateway.publicKeyHex);
    expect((await client.ensureVerified("test-model")).hpkePublicKey).toBe(gateway.publicKeyHex);
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
    const c = await createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL }, own);
    await c.ensureVerified("test-model");
    const fetched = own.calls.length;
    await c.close();
    await c.close();
    expect(c.current).toHaveLength(1);
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
      { verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL, modelPins: new Map([["other", { repo: "tinfoilsh/pinned-elsewhere" }]]) },
      seams(),
    );
    await expect(swapped.ensureVerified("other")).rejects.toBeInstanceOf(AttestationError);
  });

  it("falls over to the replica the caller's check accepts", async () => {
    const checked: string[] = [];
    const c = await createGatewayHTTPClient(
      {
        verifier: verifier(gateway.publicKeyHex),
        url: GATEWAY_URL,
        verificationCheck: (v) => {
          checked.push(v.hpkePublicKey!);
          if (checked.length === 1) throw new Error("not this replica");
        },
      },
      seams(),
    );
    const res = await c.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body: '{"model":"test-model"}', headers: { "content-type": "application/json", "x-raw": "1" } });
    expect(res.status).toBe(200);
    expect(checked).toHaveLength(2);
    expect(c.current.map((r) => r.host)).toHaveLength(1);
    expect(gateway.seen[gateway.seen.length - 1]!.headers["x-tinfoil-seal"]).toBe(c.current[0]!.host);
  });

  it("falls over to a replica that verifies and runs the caller's check", async () => {
    const checked: string[] = [];
    const failing = seams({
      documentFetch: async (input, init) => {
        const enclave = new URL(String(input)).searchParams.get("enclave");
        return enclave === "replica-a.example" ? new Response("no", { status: 503 }) : toLocal()(input, init);
      },
    });
    const c = await createGatewayHTTPClient({ verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL, verificationCheck: (v) => void checked.push(v.hpkePublicKey!) }, failing);
    const res = await c.fetch(`${GATEWAY_URL}chat/completions`, { method: "POST", body: '{"model":"test-model"}', headers: { "content-type": "application/json", "x-raw": "1" } });
    expect(res.status).toBe(200);
    expect(c.current.map((r) => r.host)).toEqual(["replica-b.example"]);
    expect(checked).toEqual([gateway.publicKeyHex]);
    expect(() => new (GatewayHTTPClient as unknown as new (...a: unknown[]) => unknown)(Symbol("x"))).toThrow(ConfigurationError);
  });
});

describe("GatewayOpenAIClient", () => {
  it("backs an OpenAI client on the gateway URL with the option's secret", async () => {
    const ai = await createGatewayOpenAIClient({ verifier: verifier(gateway.publicKeyHex), url: GATEWAY_URL, userCacheSecret: "option-secret" }, { apiKey: "k" }, seams({ resolveSecret: undefined }));
    expect(ai).toBeInstanceOf(GatewayOpenAIClient);
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
    expect(() => new (GatewayOpenAIClient as unknown as new (...a: unknown[]) => unknown)(Symbol("x"), ai.httpClient, {})).toThrow(ConfigurationError);
  });
});
