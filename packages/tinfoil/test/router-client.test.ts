/**
 * The router clients on local servers with a mocked router list: option
 * checks before any network I/O, both transport modes end to end with the
 * cache secret spliced into the request body, the failure categories when
 * the route can't be verified, and the recommended client's wiring.
 */
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { Agent } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PROTOCOL } from "ehbp";
import { APIConnectionError } from "openai";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { AttestationError, ConfigurationError, findTinfoilError, NetworkError, TinfoilError } from "../src/errors.js";
import type { RuntimeGlobals } from "../src/internal/platform.js";
import { resetProcessUserCacheSecretForTests } from "../src/internal/cachesecret.js";
import { createTinfoilClient, OpenAIClient } from "../src/openai-client.js";
import type { Fetch, RouterOptions, Transport } from "../src/options.js";
import { createRouterHTTPClient, RouterHTTPClient, type RouterClientSeams } from "../src/router-client.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type VerificationReport, type VerifiedFacts, type Verifier } from "../../verifier/src/index.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";
import { recordingFetch } from "./helpers/network.js";
import { startTlsServer, TEST_CERT, TEST_PIN, type TlsServer } from "./helpers/tls-server.js";
import { expectWithOptionsRefusesTransportOptions } from "./helpers/transport-options.js";
import { openAIOver } from "./helpers/openai.js";
import { lastFacts, verifiedReport } from "./helpers/report.js";

const ROUTER_REPO = "tinfoilsh/confidential-model-router";
const BODY = '{"model":"test","messages":[{"role":"user","content":"hi"}],"seed":9223372036854775807,"metadata":{"a":{"b":[1,2.50]}}}';

let tls: TlsServer;
let ehbp: EhbpServer;

function verifier(keys: { tls?: string; hpke?: string }, expiresAt: () => Date = () => new Date(Date.now() + 60_000)): Verifier {
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
        freshnessExpiresAt: expiresAt(),
      });
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
  return Object.assign(state, { routersFetch, documentFetch, sleep: async () => {}, shuffle: <T>(items: readonly T[]) => [...items], tls: { ca: TEST_CERT }, resolveSecret: (s: string | undefined) => s || "resolved-secret", ...extra });
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
    const s = seams(["r1.example"], { verifier: verifier({ tls: TEST_PIN }) });
    const network = recordingFetch((input, init) => fetch(input, init));
    const cases: RouterOptions[] = [
      { transport: { kind: "quic" } as unknown as Transport },
      { transport: { kind: "ehbp", fetch: "fetch" as never } },
      { transport: { kind: "ehbp", proxyURL: "http://proxy.example/" } },
      { transport: { kind: "ehbp", proxyURL: "https://user@proxy.example/" } },
      { transport: { kind: "ehbp", proxyURL: "https://proxy.example/v1/?key=1" } },
      { transport: { kind: "ehbp", proxyURL: "https://proxy.example/v1/#frag" } },
    ];
    for (const options of cases) {
      await expect(createRouterHTTPClient(options, s), JSON.stringify(options.transport)).rejects.toBeInstanceOf(ConfigurationError);
    }
    expect(s.listCalls).toBe(0);
    expect(s.documentHosts).toEqual([]);
    expect(network.seen).toHaveLength(0);
  });

  it("moves past a router that attests but fails the caller's check, and keeps the next", async () => {
    const checked: string[] = [];
    const s = seams(["first.example", tls.host]);
    const client = await createRouterHTTPClient(
      { transport: { kind: "tls" }, verificationCheck: (v) => {
          checked.push(v.tlsPublicKeyFP!);
          if (checked.length === 1) throw new Error("not this router");
        } },
      { ...s, verifier: verifier({ tls: TEST_PIN }) });
    expect(client.enclave).toBe(tls.host);
    expect(s.documentHosts).toEqual(["first.example", tls.host]);
    expect(checked).toHaveLength(2);
  });

  it("closes the transport when the signal cuts the fallback's verification short, so what that verification binds is released when it finishes", async () => {
    const destroyed = vi.spyOn(Agent.prototype, "destroy");
    try {
      let begun!: () => void;
      let serve!: () => void;
      const started = new Promise<void>((resolve) => (begun = resolve));
      const held = new Promise<void>((resolve) => (serve = resolve));
      const s = seams([], {
        documentFetch: async () => {
          begun();
          await held;
          return new Response(new Uint8Array([1]));
        },
      });
      const controller = new AbortController();
      const pending = createRouterHTTPClient({ transport: { kind: "tls" }, signal: controller.signal }, { ...s, verifier: verifier({ tls: TEST_PIN }) });
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

  it("verifies the fallback before returning and reports its failure by category", async () => {
    const unreachable = seams([], {
      documentFetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    const network = createRouterHTTPClient({}, { ...unreachable, verifier: verifier({ tls: TEST_PIN }) });
    await expect(network).rejects.toBeInstanceOf(NetworkError);

    const keyless = seams([]);
    const attestation = createRouterHTTPClient({}, { ...keyless, verifier: verifier({}) });
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
    client = await createRouterHTTPClient({ transport: { kind: "tls" } }, { ...s, verifier: verifier({ tls: TEST_PIN }) });
  });

  it("binds to the first router that verifies without verifying it again", () => {
    expect(Object.keys(client)).toEqual(["fetch", "baseURL", "enclave"]);
    expect(() => ((client as { enclave: string }).enclave = "evil.example")).toThrow(TypeError);
    expect(client.enclave).toBe(tls.host);
    expect(client.baseURL).toBe(`https://${tls.host}/`);
    expect(lastFacts(client)?.tlsPublicKeyFP).toBe(TEST_PIN);
    expect(s.documentHosts.filter((h) => h === tls.host)).toHaveLength(1);
  });

  it("stops a verification call waiting when its signal aborts, rejecting with the signal's own reason and leaving the verification in place", async () => {
    const reason = new Error("gave up");
    const signal = AbortSignal.abort(reason);
    const verified = s.documentHosts.length;
    await expect(client.reverify({ signal })).rejects.toBe(reason);
    await expect(client.ensureVerified({ signal })).rejects.toBe(reason);
    expect(lastFacts(client)?.tlsPublicKeyFP).toBe(TEST_PIN);
    expect(s.documentHosts).toHaveLength(verified);
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
    const ai = await openAIOver(createRouterHTTPClient({ transport: { kind: "tls" }, userCacheSecret: "option-secret" }, { ...seams([tls.host], { resolveSecret: undefined }), verifier: verifier({ tls: TEST_PIN }) }), { apiKey: "k" });
    expect(ai.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(ai.httpClient).toBeInstanceOf(RouterHTTPClient);
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("pinned");
    const last = tls.seen[tls.seen.length - 1]!;
    expect(JSON.parse(new TextDecoder().decode(last.body)).user_cache_secret).toBe("option-secret");
    expect(last.headers.authorization).toBe("Bearer k");
    expect(() => new OpenAIClient(Symbol("x") as never)).toThrow(ConfigurationError);
    expect(() => new (RouterHTTPClient as any)(Symbol("x"))).toThrow(ConfigurationError);
    expectWithOptionsRefusesTransportOptions(ai);
  });
});

describe("RouterHTTPClient after a failed re-verification", () => {
  it("verifies the same router again on the next request after an attestation failure, without discovering a router again", async () => {
    const fail = { attestation: false };
    const pinned = verifier({ tls: TEST_PIN });
    const s = seams([tls.host]);
    const client = await createRouterHTTPClient(
      { transport: { kind: "tls" } },
      {
        ...s,
        verifier: {
          ...pinned,
          verifyV3At: async (...args: Parameters<Verifier["verifyV3At"]>) => {
            if (fail.attestation) throw new Error("nonce mismatch");
            return pinned.verifyV3At(...args);
          },
        } as unknown as Verifier,
      },
    );
    const seen = tls.seen.length;
    fail.attestation = true;
    await expect(client.reverify()).rejects.toThrow(AttestationError);
    await expect(client.fetch(`${tls.origin}/v1/chat/completions`, { method: "POST", headers: { "x-raw": "1" }, body: BODY })).rejects.toThrow(AttestationError);
    expect(tls.seen.length).toBe(seen);

    fail.attestation = false;
    const res = await client.fetch(`${tls.origin}/v1/chat/completions`, { method: "POST", headers: { "x-raw": "1" }, body: BODY });
    expect(res.status).toBe(200);
    expect(tls.seen.length).toBe(seen + 1);
    expect(s.listCalls).toBe(1);
    expect(s.documentHosts.every((h) => h === tls.host)).toBe(true);
    await client.close();
  });
});

describe("the router clients' default cache secret", () => {
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, secret: process.env.TINFOIL_USER_CACHE_SECRET };
  let home: string;

  beforeAll(() => {
    // A secret in the environment and one in a file under the home directory, neither of which the clients may use.
    home = mkdtempSync(join(tmpdir(), "tinfoil-secret-"));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.TINFOIL_USER_CACHE_SECRET = "from-env";
    mkdirSync(join(home, ".tinfoil"), { mode: 0o700 });
    writeFileSync(join(home, ".tinfoil", "user_cache_secret"), "from-file", { mode: 0o600 });
  });

  afterAll(() => {
    for (const name of ["HOME", "USERPROFILE"] as const) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
    if (saved.secret === undefined) delete process.env.TINFOIL_USER_CACHE_SECRET;
    else process.env.TINFOIL_USER_CACHE_SECRET = saved.secret;
    rmSync(home, { recursive: true, force: true });
  });

  async function sent(client: RouterHTTPClient, body: string): Promise<string> {
    return (await client.fetch(`${tls.origin}/v1/chat/completions`, { method: "POST", body, headers: { "x-raw": "1" } })).text();
  }

  it("is one in-memory secret that every client in the process shares, ignoring the environment and the home directory", async () => {
    const options = { transport: { kind: "tls" } } as const;
    const first = await createRouterHTTPClient(options, seams([tls.host], { resolveSecret: undefined, verifier: verifier({ tls: TEST_PIN }) }));
    const second = await createRouterHTTPClient(options, seams([tls.host], { resolveSecret: undefined, verifier: verifier({ tls: TEST_PIN }) }));
    const a = JSON.parse(await sent(first, BODY)).user_cache_secret as string;
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.parse(await sent(second, BODY)).user_cache_secret).toBe(a);
    expect(await sent(second, BODY)).toBe(`${BODY.slice(0, -1)},"user_cache_secret":"${a}"}`);
    // A body's own secret still wins, and the option still overrides the generated one.
    const own = '{"user_cache_secret":"per-user"}';
    expect(await sent(first, own)).toBe(own);
    const pinned = await createRouterHTTPClient({ ...options, userCacheSecret: "option-secret" }, seams([tls.host], { resolveSecret: undefined, verifier: verifier({ tls: TEST_PIN }) }));
    expect(JSON.parse(await sent(pinned, BODY)).user_cache_secret).toBe("option-secret");
    expect(readFileSync(join(home, ".tinfoil", "user_cache_secret"), "utf8")).toBe("from-file");
    expect(readdirSync(join(home, ".tinfoil"))).toEqual(["user_cache_secret"]);
    for (const c of [first, second, pinned]) await c.close();
  });

  it("fails construction with the random source's own error before any network I/O, and generates again next time", async () => {
    resetProcessUserCacheSecretForTests();
    const failure = new Error("no secure randomness");
    const random = vi.spyOn(crypto, "getRandomValues").mockImplementationOnce(() => {
      throw failure;
    });
    try {
      const s = seams([tls.host], { resolveSecret: undefined, verifier: verifier({ tls: TEST_PIN }) });
      await expect(createRouterHTTPClient({ transport: { kind: "tls" } }, s)).rejects.toBe(failure);
      expect(s.listCalls).toBe(0);
      const client = await createRouterHTTPClient({ transport: { kind: "tls" } }, seams([tls.host], { resolveSecret: undefined, verifier: verifier({ tls: TEST_PIN }) }));
      expect(JSON.parse(await sent(client, BODY)).user_cache_secret).toMatch(/^[0-9a-f]{64}$/);
      await client.close();
    } finally {
      random.mockRestore();
    }
  });
});

describe("RouterHTTPClient.close", () => {
  it("refuses further use, keeps the last verification, and closes again without effect", async () => {
    const s = seams([tls.host]);
    const client = await createRouterHTTPClient({ transport: { kind: "tls" } }, { ...s, verifier: verifier({ tls: TEST_PIN }) });
    const verified = s.documentHosts.length;
    await client.close();
    await client.close();
    expect(lastFacts(client)?.tlsPublicKeyFP).toBe(TEST_PIN);
    await expect(client.fetch(`${tls.origin}/v1/models`)).rejects.toThrow(/client is closed/);
    await expect(client.ensureVerified()).rejects.toBeInstanceOf(ConfigurationError);
    await expect(client.reverify()).rejects.toThrow(/client is closed/);
    expect(s.documentHosts).toHaveLength(verified);
  });
});

describe("RouterHTTPClient over EHBP", () => {
  it("reaches the discovered router through a proxy, sealing the body with the secret spliced in", async () => {
    const s = seams(["router.example"]);
    const client = await createRouterHTTPClient(
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` } },
      { ...s, verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) });
    expect(client.enclave).toBe("router.example");
    expect(client.baseURL).toBe(`${ehbp.origin}/`);
    const res = await client.fetch(`${ehbp.origin}/v1/chat/completions`, { method: "POST", body: BODY, headers: { "x-raw": "1" } });
    expect(await res.text()).toBe(`${BODY.slice(0, -1)},"user_cache_secret":"resolved-secret"}`);
    const last = ehbp.seen[ehbp.seen.length - 1]!;
    expect(last.sealed).toBe(true);
    expect(last.headers["x-tinfoil-enclave-url"]).toBe("https://router.example");
  });

  it("ends the proxy base URL with a slash, resolves a relative path under it, and keeps requests on its origin", async () => {
    const client = await createRouterHTTPClient(
      { transport: { kind: "ehbp", proxyURL: ehbp.origin } },
      { ...seams(["router.example"]), verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) });
    expect(client.baseURL).toBe(`${ehbp.origin}/`);
    const res = await client.fetch(new URL("v1/echo", client.baseURL), { method: "POST", body: "under", headers: { "x-raw": "1" } });
    expect(await res.text()).toBe("under");
    expect(ehbp.seen[ehbp.seen.length - 1]!.path).toBe("/v1/echo");
    await expect(client.fetch("https://other.example/v1/echo")).rejects.toThrow(/client is bound to enclave/);
    const padded = await createRouterHTTPClient(
      { transport: { kind: "ehbp", proxyURL: `  ${ehbp.origin}/v1  ` } },
      { ...seams(["router.example"]), verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) });
    expect(padded.baseURL).toBe(`${ehbp.origin}/v1/`);
  });

  it("backs an OpenAI client on the proxy base URL", async () => {
    const ai = await openAIOver(createRouterHTTPClient({ transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` } }, { ...seams(["router.example"]), verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) }), { apiKey: "k" });
    expect(ai.baseURL).toBe(`${ehbp.origin}/v1/`);
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("sealed");
    expect(ehbp.seen[ehbp.seen.length - 1]!.path).toBe("/v1/chat/completions");
  });

  it("sends sealed requests through the fetch option, with the secret spliced in before sealing, while discovery keeps its own fetches", async () => {
    const network = recordingFetch((input, init) => fetch(input, init));
    const s = seams(["router.example"]);
    const client = await createRouterHTTPClient(
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/`, fetch: network.fetch } },
      { ...s, verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) });
    expect(s.listCalls).toBe(1);
    expect(s.documentHosts).toEqual(["router.example"]);
    expect(network.seen).toHaveLength(0);

    const res = await client.fetch(`${ehbp.origin}/v1/chat/completions`, { method: "POST", body: BODY, headers: { "x-raw": "1", authorization: "Bearer k" } });
    expect(await res.text()).toBe(`${BODY.slice(0, -1)},"user_cache_secret":"resolved-secret"}`);
    expect(network.seen).toHaveLength(1);
    const sealed = network.seen[0]!;
    expect(sealed.url).toBe(`${ehbp.origin}/v1/chat/completions`);
    expect(sealed.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER)).toBe(true);
    expect(sealed.headers.get("x-tinfoil-enclave-url")).toBe("https://router.example");
    expect(sealed.headers.get("authorization")).toBe("Bearer k");
    expect(sealed.body).not.toContain("resolved-secret");
    expect(sealed.body).not.toContain("messages");

    const bodiless = await client.fetch(`${ehbp.origin}/v1/echo`, { headers: { "x-raw": "1" } });
    expect(await bodiless.text()).toBe("");
    expect(network.seen).toHaveLength(2);
    expect(network.seen[1]!.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER)).toBe(false);

    const ai = await openAIOver(createRouterHTTPClient({ transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/`, fetch: network.fetch } }, { ...seams(["router.example"]), verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }) }), { apiKey: "k" });
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("sealed");
    expect(network.seen).toHaveLength(3);
    expect(network.seen[2]!.url).toBe(`${ehbp.origin}/v1/chat/completions`);
    expect(network.seen[2]!.headers.get("authorization")).toBe("Bearer k");
    expect(network.seen[2]!.body).not.toContain("hi");
  });
});

describe("createClient", () => {
  it("creates the recommended client over the discovered router", async () => {
    const s = seams([tls.host]);
    const ai = await createTinfoilClient({ apiKey: "k" }, { ...s, verifier: verifier({ tls: TEST_PIN }) }, {});
    expect(ai).toBeInstanceOf(OpenAIClient);
    expect(ai.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(ai.httpClient).toBeInstanceOf(RouterHTTPClient);
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("pinned");
    expect(JSON.parse(new TextDecoder().decode(tls.seen[tls.seen.length - 1]!.body)).user_cache_secret).toBe("resolved-secret");
    expect(() => new (OpenAIClient as any)(Symbol("x"), ai.httpClient, {})).toThrow(ConfigurationError);
    expectWithOptionsRefusesTransportOptions(ai);
  });

  it("accepts an API key on a server and refuses one anywhere else before fetching anything", async () => {
    const server = await createTinfoilClient({ apiKey: "k", dangerouslyAllowBrowser: true }, { ...seams([tls.host]), verifier: verifier({ tls: TEST_PIN }) }, {});
    expect(server.apiKey).toBe("k");
    expect(server.withOptions({ apiKey: "k2" }).apiKey).toBe("k2");
    const worker = { self: {} } as unknown as RuntimeGlobals;
    const s = seams([tls.host]);
    for (const factory of [
      () => createTinfoilClient({ apiKey: "k" }, { verifier: verifier({ tls: TEST_PIN }), ...s, globals: worker }, {}),
      () => createTinfoilClient({ apiKey: "k", dangerouslyAllowBrowser: true }, { verifier: verifier({ tls: TEST_PIN }), ...s, globals: worker }, {}),
    ]) {
      const failure = factory();
      await expect(failure).rejects.toBeInstanceOf(ConfigurationError);
      await expect(failure).rejects.toThrow(/belongs on a server; in a browser, give a bearerToken/);
    }
    expect(s.listCalls).toBe(0);
    expect(s.documentHosts).toEqual([]);
    // A bearer token is the credential a worker holds; it is accepted there over sealed bodies.
    const tokened = await createTinfoilClient(
      { bearerToken: "t" },
      { verifier: verifier({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex }), ...seams(["router.example"]), globals: worker },
      { transport: { kind: "ehbp", proxyURL: `${ehbp.origin}/` } });
    expect(tokened.apiKey).toBe("t");
  });
});

describe("errors through the OpenAI API surface", () => {
  /** A client whose verification has expired and is rejected whenever it verifies again, so every request's fetch throws an AttestationError. */
  async function expiredClient(): Promise<{ ai: OpenAIClient; checks: () => number }> {
    let now = Date.now();
    let checks = 0;
    const ai = await createTinfoilClient(
      { apiKey: "k" },
      { verifier: verifier({ tls: TEST_PIN }, () => new Date(now + 60_000)), ...seams([tls.host]), clock: () => new Date(now) },
      { transport: { kind: "tls" }, verificationCheck: () => {
          if (checks++ > 0) throw new Error("rejected on refresh");
        } });
    expect(checks).toBe(1);
    now += 120_000;
    return { ai, checks: () => checks - 1 };
  }
  const rejection = (p: Promise<unknown>): Promise<Error> => p.then(() => Promise.reject(new Error("resolved")), (e: unknown) => e as Error);
  const request = { model: "test", messages: [{ role: "user" as const, content: "hi" }] };

  it("wraps a transport error in APIConnectionError with the error as its cause, after the OpenAI client's retries", async () => {
    const { ai, checks } = await expiredClient();
    const failure = await rejection(ai.chat.completions.create(request));
    expect(failure).toBeInstanceOf(APIConnectionError);
    expect(failure.cause).toBeInstanceOf(AttestationError);
    expect((failure.cause as Error).message).toMatch(/rejected on refresh/);
    expect(findTinfoilError(failure)).toBe(failure.cause);
    // The default maxRetries of 2 means three attempts, each verifying again.
    expect(checks()).toBe(3);
  }, 15_000);

  it("retries a streamed completion as well, and makes one attempt with maxRetries 0", async () => {
    const { ai, checks } = await expiredClient();
    const streamed = await rejection(ai.chat.completions.create({ ...request, stream: true }));
    expect(streamed).toBeInstanceOf(APIConnectionError);
    expect(streamed.cause).toBeInstanceOf(AttestationError);
    expect(checks()).toBe(3);
    const once = await rejection(ai.withOptions({ maxRetries: 0 }).chat.completions.create(request));
    expect(once).toBeInstanceOf(APIConnectionError);
    expect(once.cause).toBeInstanceOf(AttestationError);
    expect(findTinfoilError(once)?.category).toBe("attestation");
    expect(checks()).toBe(4);
    const perRequest = await rejection(ai.chat.completions.create(request, { maxRetries: 0 }));
    expect(perRequest.cause).toBeInstanceOf(AttestationError);
    expect(checks()).toBe(5);
  }, 15_000);
});
