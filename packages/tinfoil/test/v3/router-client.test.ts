/**
 * The router clients on local servers with a mocked router list: option
 * checks before any network I/O, both transport modes end to end with the
 * cache secret spliced into the request body, the failure categories when
 * the route can't be verified, and the recommended client's wiring.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, NetworkError, TinfoilError } from "../../src/v3/errors.js";
import { createRouterOpenAIClient, createTinfoilClient, RouterOpenAIClient, TinfoilClient } from "../../src/v3/openai-client.js";
import type { Fetch, RouterOptions } from "../../src/v3/options.js";
import { createRouterHTTPClient, RouterHTTPClient, type RouterClientSeams } from "../../src/v3/router-client.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verification, type Verifier } from "../../../verifier/src/index.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";
import { startTlsServer, TEST_CERT, TEST_PIN, type TlsServer } from "./helpers/tls-server.js";

const ROUTER_REPO = "tinfoilsh/confidential-model-router";
const BODY = '{"model":"test","messages":[{"role":"user","content":"hi"}],"seed":9223372036854775807,"metadata":{"a":{"b":[1,2.50]}}}';

let tls: TlsServer;
let ehbp: EhbpServer;

function verifier(keys: { tls?: string; hpke?: string }, authorizes = false): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo === "") throw new UsageError("repo required");
    },
    callerAuthorizesConfig: () => authorizes,
    verifyV3At: async () => {
      const material = [
        ...(keys.tls === undefined ? [] : [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: keys.tls }]),
        ...(keys.hpke === undefined ? [] : [{ id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: keys.hpke }]),
      ];
      return {
        cryptoMaterial: () => material.map((m) => ({ ...m })),
        tlsPublicKeyFP: () => keys.tls,
        hpkePublicKey: () => keys.hpke,
        codeDigest: () => "11".repeat(32),
        freshnessExpiresAt: () => new Date(Date.now() + 60_000),
      } as unknown as Verification;
    },
  } as unknown as Verifier;
}

function seams(routers: string[], extra: Partial<RouterClientSeams> = {}): RouterClientSeams & { documentHosts: string[]; listCalls: number } {
  const state = { documentHosts: [] as string[], listCalls: 0 };
  const routersFetch: Fetch = async () => {
    state.listCalls++;
    return new Response(JSON.stringify(routers));
  };
  const documentFetch: Fetch = async (input) => {
    state.documentHosts.push(new URL(String(input)).host);
    return new Response(new Uint8Array([1]));
  };
  return Object.assign(state, { routersFetch, documentFetch, sleep: async () => {}, tls: { ca: TEST_CERT }, resolveSecret: async (s: string | undefined) => s || "resolved-secret", ...extra });
}

function completion(content: string): unknown {
  return { id: "c", object: "chat.completion", created: 1, model: "test", choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }] };
}

beforeAll(async () => {
  tls = await startTlsServer((seen) =>
    seen.path === "/v1/chat/completions" && seen.headers["x-raw"] === undefined
      ? { headers: { "content-type": "application/json" }, body: JSON.stringify(completion("pinned")) }
      : { headers: { "content-type": "text/plain" }, body: seen.body },
  );
  ehbp = await startEhbpServer((seen) =>
    seen.headers["x-raw"] === undefined
      ? { headers: { "content-type": "application/json" }, body: JSON.stringify(completion("sealed")) }
      : { headers: { "content-type": "text/plain" }, body: new TextDecoder().decode(seen.body) },
  );
});

afterAll(async () => {
  await Promise.all([tls.close(), ehbp.close()]);
});

describe("RouterHTTPClient.create", () => {
  it("checks its options before fetching anything", async () => {
    const s = seams(["r1.example"]);
    const cases: RouterOptions[] = [
      { verifier: verifier({ tls: TEST_PIN }), transportMode: "quic" as never },
      { verifier: verifier({ tls: TEST_PIN }), baseURL: "https://proxy.example/" },
      { verifier: verifier({ tls: TEST_PIN }), transportMode: "tls", baseURL: "https://proxy.example/" },
      { verifier: verifier({ tls: TEST_PIN }), transportMode: "ehbp", baseURL: "http://proxy.example/" },
      { verifier: verifier({ tls: TEST_PIN }, true) },
    ];
    for (const options of cases) {
      await expect(createRouterHTTPClient(options, s), JSON.stringify(options.baseURL)).rejects.toBeInstanceOf(ConfigurationError);
    }
    expect(s.listCalls).toBe(0);
    expect(s.documentHosts).toEqual([]);
  });

  it("moves past a router that attests but fails the caller's check, and keeps the next", async () => {
    const checked: string[] = [];
    const s = seams(["first.example", tls.host]);
    const client = await createRouterHTTPClient(
      {
        verifier: verifier({ tls: TEST_PIN }),
        transportMode: "tls",
        verificationCheck: (v) => {
          checked.push(v.tlsPublicKeyFP()!);
          if (checked.length === 1) throw new Error("not this router");
        },
      },
      s,
    );
    expect(client.enclave()).toBe(tls.host);
    expect(s.documentHosts).toEqual(["first.example", tls.host]);
    expect(checked).toHaveLength(2);
  });

  it("verifies the fallback before returning and reports its failure by category", async () => {
    const unreachable = seams([], {
      documentFetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    const network = createRouterHTTPClient({ verifier: verifier({ tls: TEST_PIN }) }, unreachable);
    await expect(network).rejects.toBeInstanceOf(NetworkError);

    const keyless = seams([]);
    const attestation = createRouterHTTPClient({ verifier: verifier({}) }, keyless);
    await expect(attestation).rejects.toBeInstanceOf(AttestationError);
    expect(keyless.documentHosts.every((h) => h === "inference.tinfoil.sh")).toBe(true);
    await expect(attestation).rejects.toBeInstanceOf(TinfoilError);
  });
});

describe("RouterHTTPClient over TLS", () => {
  let client: RouterHTTPClient;
  let s: ReturnType<typeof seams>;

  beforeAll(async () => {
    const hosts: string[] = [];
    s = seams(["unverifiable.example", tls.host], {
      documentFetch: async (input) => {
        const host = new URL(String(input)).host;
        hosts.push(host);
        return host === "unverifiable.example" ? new Response("no", { status: 503 }) : new Response(new Uint8Array([1]));
      },
    });
    s.documentHosts = hosts;
    client = await createRouterHTTPClient({ verifier: verifier({ tls: TEST_PIN }), transportMode: "tls" }, s);
  });

  it("binds to the first router that verifies without verifying it again", () => {
    expect(client.enclave()).toBe(tls.host);
    expect(client.repo()).toBe(ROUTER_REPO);
    expect(client.baseURL()).toBe(`https://${tls.host}/`);
    expect(client.current()?.tlsPublicKeyFP()).toBe(TEST_PIN);
    expect(s.documentHosts.filter((h) => h === tls.host)).toHaveLength(1);
  });

  it("splices the cache secret into the body over the pinned connection, preserving the caller's bytes", async () => {
    const res = await client.fetch(`${tls.origin}/v1/chat/completions`, { method: "POST", body: BODY, headers: { "x-raw": "1" } });
    expect(await res.text()).toBe(`${BODY.slice(0, -1)},"user_cache_secret":"resolved-secret"}`);
    const embeddings = await client.fetch(`${tls.origin}/v1/embeddings`, { method: "POST", body: BODY, headers: { "x-raw": "1" } });
    expect(await embeddings.text()).toBe(BODY);
    await expect(client.fetch("https://other.example/v1/chat/completions")).rejects.toThrow(/client is bound to enclave/);
  });

  it("keeps the secret a request's body sets and forwards a non-JSON body untouched", async () => {
    const own = '{"user_cache_secret":"per-user"}';
    expect(await (await client.fetch(`${tls.origin}/v1/responses`, { method: "POST", body: own, headers: { "x-raw": "1" } })).text()).toBe(own);
    expect(await (await client.fetch(`${tls.origin}/v1/completions`, { method: "POST", body: "plain text", headers: { "x-raw": "1" } })).text()).toBe("plain text");
  });

  it("backs an OpenAI client on the router's /v1/ API with the option's secret", async () => {
    const ai = await createRouterOpenAIClient(
      { verifier: verifier({ tls: TEST_PIN }), transportMode: "tls", userCacheSecret: "option-secret" },
      { apiKey: "k" },
      seams([tls.host], { resolveSecret: undefined }),
    );
    expect(ai.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(ai.httpClient()).toBeInstanceOf(RouterHTTPClient);
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("pinned");
    const last = tls.seen[tls.seen.length - 1]!;
    expect(JSON.parse(new TextDecoder().decode(last.body)).user_cache_secret).toBe("option-secret");
    expect(last.headers.authorization).toBe("Bearer k");
    expect(() => new (RouterOpenAIClient as unknown as new (...a: unknown[]) => unknown)(Symbol("x"), ai.httpClient(), {})).toThrow(ConfigurationError);
    expect(() => new (RouterHTTPClient as unknown as new (...a: unknown[]) => unknown)(Symbol("x"))).toThrow(ConfigurationError);
  });
});

describe("RouterHTTPClient over EHBP", () => {
  it("reaches the discovered router through a proxy, sealing the body with the secret spliced in", async () => {
    const s = seams(["router.example"]);
    const client = await createRouterHTTPClient(
      { verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }), transportMode: "ehbp", baseURL: `${ehbp.origin}/` },
      s,
    );
    expect(client.enclave()).toBe("router.example");
    expect(client.baseURL()).toBe(`${ehbp.origin}/`);
    const res = await client.fetch(`${ehbp.origin}/v1/chat/completions`, { method: "POST", body: BODY, headers: { "x-raw": "1" } });
    expect(await res.text()).toBe(`${BODY.slice(0, -1)},"user_cache_secret":"resolved-secret"}`);
    const last = ehbp.seen[ehbp.seen.length - 1]!;
    expect(last.sealed).toBe(true);
    expect(last.headers["x-tinfoil-enclave-url"]).toBe("https://router.example");
  });

  it("backs an OpenAI client on the proxy base URL", async () => {
    const ai = await createRouterOpenAIClient(
      { verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }), transportMode: "ehbp", baseURL: `${ehbp.origin}/` },
      { apiKey: "k" },
      seams(["router.example"]),
    );
    expect(ai.baseURL).toBe(`${ehbp.origin}/`);
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("sealed");
    expect(ehbp.seen[ehbp.seen.length - 1]!.path).toBe("/chat/completions");
  });
});

describe("createClient", () => {
  it("creates the recommended client over the discovered router", async () => {
    const s = seams([tls.host]);
    const ai = await createTinfoilClient({ apiKey: "k" }, s, { verifier: verifier({ tls: TEST_PIN }) });
    expect(ai).toBeInstanceOf(TinfoilClient);
    expect(ai.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(ai.httpClient()).toBeInstanceOf(RouterHTTPClient);
    expect(ai.httpClient().repo()).toBe(ROUTER_REPO);
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("pinned");
    expect(JSON.parse(new TextDecoder().decode(tls.seen[tls.seen.length - 1]!.body)).user_cache_secret).toBe("resolved-secret");
    expect(() => new (TinfoilClient as unknown as new (...a: unknown[]) => unknown)(Symbol("x"), ai.httpClient(), {})).toThrow(ConfigurationError);
  });
});
