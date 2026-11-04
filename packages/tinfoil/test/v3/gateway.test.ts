/**
 * The gateway internals: catalog parsing and the refresh cache, the policy's
 * pin checks and resolution, request preparation (the model header, the
 * cache scope against the specification's vector, uploads), replica ranking,
 * and the transport's fall-over, rerouting and verification bookkeeping
 * over replicas behind a mocked gateway.
 */
import { Identity } from "ehbp";
import { beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, NetworkError } from "../../src/v3/errors.js";
import { CATALOG_REFRESH_INTERVAL_MS, CatalogCache, fetchCatalogWith, MAX_CATALOG_BYTES, parseCatalog } from "../../src/v3/internal/gateway/catalog.js";
import { GatewayPolicy } from "../../src/v3/internal/gateway/policy.js";
import { bearerCredential, CACHE_PREFIX_HEADER, MODEL_HEADER, multipartModel, prepare, scopeCache } from "../../src/v3/internal/gateway/prepare.js";
import { GatewayTransport, MAX_SEAL_REDIRECTS, rank, SEAL_HEADER, type GatewayTransportConfig } from "../../src/v3/internal/gateway/transport.js";
import { shapeOf } from "../../src/v3/internal/transport/transport.js";
import type { Catalog, Fetch } from "../../src/v3/options.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verification, type Verifier } from "../../../verifier/src/v3/index.js";
import { createEhbpPeer, fetchOf, type EhbpPeer } from "./helpers/ehbp-peer.js";

const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s) as Uint8Array<ArrayBuffer>;
/** The enclave an attestation request through the gateway relay is for. */
const enclaveOf = (input: string | URL | Request): string => new URL(String(input)).searchParams.get("enclave") ?? "";
const catalogOf = (entries: Record<string, { repo: string; hosts: string[] }>): Catalog => new Map(Object.entries(entries));

/** A verifier accepting every document, whose verifications carry `hpke`; `authorizes` makes it caller-authorized. */
function verifier(hpke: string, authorizes = false, seen: string[] = []): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo === "") throw new UsageError("repo required");
    },
    callerAuthorizesConfig: () => authorizes,
    verifyV3At: async (_doc: Uint8Array, _nonce: Uint8Array, repo: string) => {
      seen.push(repo);
      const material = [
        { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) },
        { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke },
      ];
      return {
        cryptoMaterial: () => material.map((m) => ({ ...m })),
        tlsPublicKeyFP: () => "ab".repeat(32),
        hpkePublicKey: () => hpke,
        codeDigest: () => "11".repeat(32),
        freshnessExpiresAt: () => new Date(Date.now() + 60_000),
      } as unknown as Verification;
    },
  } as unknown as Verifier;
}

describe("catalog", () => {
  it("keeps only models with replicas of a bare trusted repository", () => {
    const catalog = parseCatalog(
      utf8(
        JSON.stringify({
          good: { repo: "tinfoilsh/model", hosts: ["a.example", "b.example"], context: 1 },
          tagged: { repo: "tinfoilsh/model@v1", hosts: ["a.example"] },
          digest: { repo: "tinfoilsh/model@sha256:" + "aa".repeat(32), hosts: ["a.example"] },
          other: { repo: "evil/model", hosts: ["a.example"] },
          empty: { repo: "tinfoilsh/model", hosts: [] },
          bare: null,
          nohosts: { repo: "tinfoilsh/model" },
        }),
      ),
    );
    expect([...catalog.keys()]).toEqual(["good"]);
    expect(catalog.get("good")).toEqual({ repo: "tinfoilsh/model", hosts: ["a.example", "b.example"] });
    expect(parseCatalog(utf8("null")).size).toBe(0);
    for (const bad of ["[]", '"s"', "nope", '{"m":{"repo":1}}', '{"m":{"hosts":"a"}}', '{"m":[]}']) {
      expect(() => parseCatalog(utf8(bad)), bad).toThrow(NetworkError);
    }
  });

  it("fetches over HTTPS only, requires a 200, and caps the size", async () => {
    const calls: string[] = [];
    const serve =
      (status: number, body: BodyInit, headers: Record<string, string> = {}): Fetch =>
      async (input) => {
        calls.push(String(input));
        return new Response(body, { status, headers });
      };
    const catalog = await fetchCatalogWith("gateway.example", serve(200, '{"m":{"repo":"tinfoilsh/m","hosts":["a.example"]}}'));
    expect(calls).toEqual(["https://gateway.example/catalog"]);
    expect([...catalog.keys()]).toEqual(["m"]);
    await expect(fetchCatalogWith("gateway.example", serve(503, "down"))).rejects.toBeInstanceOf(NetworkError);
    await expect(fetchCatalogWith("gateway.example", serve(201, "{}"))).rejects.toBeInstanceOf(NetworkError);
    await expect(fetchCatalogWith("gateway.example", serve(302, "", { location: "http://gateway.example/catalog" }))).rejects.toBeInstanceOf(NetworkError);
    await expect(fetchCatalogWith("gateway.example", serve(200, new Uint8Array(MAX_CATALOG_BYTES + 1).fill(0x20)))).rejects.toThrow(/exceeds/);
    await expect(
      fetchCatalogWith("gateway.example", async () => {
        throw new TypeError("fetch failed");
      }),
    ).rejects.toBeInstanceOf(NetworkError);
  });

  it("fetches on first use, shares the fetch, retries a failure on the next use, and keeps a success", async () => {
    let fetches = 0;
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const cache = new CatalogCache(async () => {
      fetches++;
      await gate;
      if (fetches === 1) throw new NetworkError("gateway unavailable");
      return catalogOf({ m: { repo: "tinfoilsh/m", hosts: ["a.example"] } });
    });
    const controller = new AbortController();
    const waiter = cache.get(controller.signal);
    const results = [cache.get(), cache.get(), cache.get()];
    controller.abort(new Error("gave up"));
    await expect(waiter).rejects.toThrow(/gave up/);
    release();
    for (const r of results) await expect(r).rejects.toThrow(/gateway unavailable/);
    expect(fetches).toBe(1);
    expect((await cache.get()).has("m")).toBe(true);
    expect((await cache.get()).has("m")).toBe(true);
    expect(fetches).toBe(2);
  });

  it("refreshes on use after the interval without blocking, and keeps the catalog over a failed refresh", async () => {
    let now = Date.parse("2026-11-04T00:00:00Z");
    const clock = () => new Date(now);
    const catalogs: (Catalog | undefined)[] = [catalogOf({ old: { repo: "tinfoilsh/old", hosts: ["a.example"] } }), undefined, catalogOf({ new: { repo: "tinfoilsh/new", hosts: ["b.example"] } })];
    const releases: (() => void)[] = [];
    let fetches = 0;
    const cache = new CatalogCache(async () => {
      const n = fetches++;
      await new Promise<void>((resolve) => releases.push(resolve));
      const catalog = catalogs[n];
      if (catalog === undefined) throw new NetworkError("gateway unavailable");
      return catalog;
    }, clock);
    const first = cache.get();
    releases.shift()!();
    expect((await first).has("old")).toBe(true);
    now += CATALOG_REFRESH_INTERVAL_MS - 1;
    expect((await cache.get()).has("old")).toBe(true);
    expect(fetches).toBe(1);
    now += 1;
    expect((await cache.get()).has("old")).toBe(true);
    expect((await cache.get()).has("old")).toBe(true);
    expect(fetches).toBe(2);
    now += CATALOG_REFRESH_INTERVAL_MS + 1;
    releases.shift()!();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect((await cache.get()).has("old")).toBe(true);
    expect(fetches).toBe(2);
    now += CATALOG_REFRESH_INTERVAL_MS;
    expect((await cache.get()).has("old")).toBe(true);
    expect(fetches).toBe(3);
    releases.shift()!();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect((await cache.get()).has("new")).toBe(true);
  });
});

describe("GatewayPolicy", () => {
  const v = verifier("ab".repeat(32));

  it("checks the pins before any network I/O", async () => {
    await expect(GatewayPolicy.create(undefined, true, v)).rejects.toThrow(/at least one model pin/);
    await expect(GatewayPolicy.create(undefined, false, verifier("", true))).rejects.toThrow(/caller-authorized config/);
    await expect(GatewayPolicy.create(new Map([["m", { repo: "tinfoilsh/m", verifier: verifier("", true) }]]), false, v)).rejects.toThrow(/model "m": caller-authorized/);
    await expect(GatewayPolicy.create(new Map([["m", { repo: "evil/m" }]]), false, v)).rejects.toThrow(/must belong to tinfoilsh\//);
    await expect(GatewayPolicy.create(new Map([[" ", { repo: "tinfoilsh/m" }]]), false, v)).rejects.toThrow(/must belong to/);
    await expect(GatewayPolicy.create(new Map([["m", { repo: "tinfoilsh/m@@" }]]), false, v)).rejects.toBeInstanceOf(ConfigurationError);
    await expect(GatewayPolicy.create(new Map([["m", { repo: "tinfoilsh/m@v1" }]]), false, v)).resolves.toBeInstanceOf(GatewayPolicy);
  });

  it("resolves pinned models against their pin and unpinned ones against the catalog", async () => {
    const pinned = verifier("cd".repeat(32));
    const policy = await GatewayPolicy.create(new Map([["pinned", { repo: "tinfoilsh/pinned@v1", verifier: pinned }]]), false, v);
    const catalog = catalogOf({
      pinned: { repo: "tinfoilsh/pinned", hosts: ["p.example"] },
      free: { repo: "tinfoilsh/free", hosts: ["f.example"] },
      swapped: { repo: "tinfoilsh/other", hosts: ["s.example"] },
    });
    expect(policy.resolve("pinned", catalog)).toEqual({ hosts: ["p.example"], replica: { ref: "tinfoilsh/pinned@v1", model: "pinned" } });
    expect(policy.resolve("free", catalog)).toEqual({ hosts: ["f.example"], replica: { ref: "tinfoilsh/free", model: "" } });
    expect(() => policy.resolve("missing", catalog)).toThrow(ConfigurationError);
    expect(policy.verifierFor({ ref: "tinfoilsh/pinned@v1", model: "pinned" })).toBe(pinned);
    expect(policy.verifierFor({ ref: "tinfoilsh/free", model: "" })).toBe(v);

    const other = await GatewayPolicy.create(new Map([["swapped", { repo: "tinfoilsh/swapped" }]]), false, v);
    expect(() => other.resolve("swapped", catalog)).toThrow(AttestationError);
    expect(() => other.resolve("swapped", catalog)).toThrow(/expected repository "tinfoilsh\/swapped", gateway offered "tinfoilsh\/other"/);

    const only = await GatewayPolicy.create(new Map([["pinned", { repo: "tinfoilsh/pinned" }]]), true, v);
    expect(() => only.resolve("free", catalog)).toThrow(/is not pinned/);
    expect(only.serves("pinned", catalog)).toBe(true);
    expect(only.serves("free", catalog)).toBe(false);
  });
});

// The cache salt and prefix of the specification's vector: secret test-secret,
// Authorization: Bearer test-api-key, and SPEC_BODY.
const SPEC_BODY = '{"model":"test-model","messages":[{"role":"user","content":"hello"}]}';
const SPEC_SALT = "DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8";
const SPEC_PREFIX = "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6";

describe("prepare", () => {
  const url = "https://gateway.example/v1/chat/completions";

  it("derives the specification's cache salt and prefix, dropping the secret and keeping the caller's bytes", async () => {
    const headers = new Headers({ "content-type": "application/json", authorization: "Bearer test-api-key" });
    const out = await prepare(shapeOf(url, { method: "POST", body: SPEC_BODY, headers }), headers, SPEC_BODY, "test-secret");
    expect(out.headers.get(MODEL_HEADER)).toBe("test-model");
    expect(out.headers.get(CACHE_PREFIX_HEADER)).toBe(SPEC_PREFIX);
    expect(out.body).toBe(`${SPEC_BODY.slice(0, -1)},"cache_salt":"${SPEC_SALT}"}`);
    expect(out.replayable).toBe(true);
  });

  it("takes the per-request secret over the client's and never forwards it", async () => {
    const scope = async (clientSecret: string, authorization: string, body: string) => {
      const headers = new Headers({ "content-type": "application/json", ...(authorization === "" ? {} : { authorization }) });
      const text = await scopeCache(headers, body, clientSecret);
      expect(text).not.toContain("user_cache_secret");
      return { salt: (JSON.parse(text) as { cache_salt?: string }).cache_salt, prefix: headers.get(CACHE_PREFIX_HEADER) };
    };
    const got = await scope("client-secret", "Bearer test-api-key", '{"model":"test-model","user_cache_secret":"end-user"}');
    const want = await scope("end-user", "Bearer test-api-key", '{"model":"test-model"}');
    expect(got).toEqual(want);
    expect((await scope("client-secret", "Bearer test-api-key", '{"model":"test-model"}')).salt).not.toBe(got.salt);
    for (const authorization of ["Bearer test-api-key", "bearer test-api-key", " BEARER  test-api-key "]) {
      expect(await scope("test-secret", authorization, SPEC_BODY), authorization).toEqual({ salt: SPEC_SALT, prefix: SPEC_PREFIX });
    }
    const noKey = await scope("test-secret", "", SPEC_BODY);
    for (const authorization of ["Basic test-api-key", "Bearertest-api-key", "Bearer"]) {
      expect(await scope("test-secret", authorization, SPEC_BODY), authorization).toEqual(noKey);
    }
    const other = await scope("test-secret", "Bearer other-api-key", SPEC_BODY);
    expect(noKey.salt).not.toBe(SPEC_SALT);
    expect(other.salt).not.toBe(SPEC_SALT);
    expect(noKey).not.toEqual(other);
    expect(bearerCredential("Bearer  k ")).toBe("k");
  });

  it("scopes with an empty-string secret member replaced and no prefix without a prompt", async () => {
    const headers = new Headers({ "content-type": "application/json", [CACHE_PREFIX_HEADER]: "stale" });
    const text = await scopeCache(headers, '{"user_cache_secret":"","model":"m"}', "s");
    expect(text).toBe(`{"model":"m","cache_salt":${JSON.stringify((JSON.parse(text) as { cache_salt: string }).cache_salt)}}`);
    expect(headers.get(CACHE_PREFIX_HEADER)).toBeNull();
    expect(await scopeCache(new Headers(), '{"model":"m"}', "")).toBe('{"model":"m"}');
    const instructions = new Headers();
    await scopeCache(instructions, '{"instructions":"be brief","input":[{"a":1}]}', "s");
    const input = new Headers();
    await scopeCache(input, '{"instructions":"","input":[{"a":1}]}', "s");
    const prompt = new Headers();
    await scopeCache(prompt, '{"prompt":"text"}', "s");
    expect(instructions.get(CACHE_PREFIX_HEADER)).not.toBe(input.get(CACHE_PREFIX_HEADER));
    expect(prompt.get(CACHE_PREFIX_HEADER)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("leaves other requests alone and takes the model from uploads", async () => {
    const plain = await prepare(shapeOf(url, { method: "POST", body: "x=1" }), new Headers({ "content-type": "text/plain" }), "x=1", "s");
    expect(plain.body).toBe("x=1");
    const get = await prepare(shapeOf("https://gateway.example/v1/models"), new Headers(), undefined, "s");
    expect(get.headers.get(MODEL_HEADER)).toBeNull();
    const embeddings = await prepare(shapeOf("https://gateway.example/v1/embeddings", { method: "POST", body: "{}" }), new Headers({ "content-type": "application/json" }), '{"model":"e","input":"x"}', "s");
    expect(embeddings.headers.get(MODEL_HEADER)).toBe("e");
    expect(embeddings.body).toBe('{"model":"e","input":"x"}');
    const explicit = await prepare(shapeOf(url, { method: "POST", body: "{}" }), new Headers({ "content-type": "application/json", [MODEL_HEADER]: "set" }), '{"model":"body"}', "");
    expect(explicit.headers.get(MODEL_HEADER)).toBe("set");
    const stream = await prepare(shapeOf(url, { method: "POST", body: "{}" }), new Headers({ "content-type": "application/json; charset=utf-8" }), new Response('{"model":"s"}').body, "");
    expect(stream.headers.get(MODEL_HEADER)).toBe("s");
    expect(stream.replayable).toBe(true);

    const form = new FormData();
    form.append("model", "whisper");
    form.append("file", new Blob(["audio"]), "a.wav");
    const upload = await prepare(shapeOf("https://gateway.example/v1/audio/transcriptions", { method: "POST", body: form }), new Headers({ "content-type": "multipart/form-data; boundary=x" }), form, "s");
    expect(upload.headers.get(MODEL_HEADER)).toBe("whisper");
    expect(upload.body).toBe(form);
    const twice = new FormData();
    twice.append("model", "a");
    twice.append("model", "b");
    await expect(prepare(shapeOf(url, { method: "POST", body: twice }), new Headers({ "content-type": "multipart/form-data; boundary=x" }), twice, "s")).rejects.toThrow(/exactly one non-empty model field/);

    const raw = ['--b', 'Content-Disposition: form-data; name="file"; filename="a.wav"', "Content-Type: audio/wav", "", "audio", "--b", 'Content-Disposition: form-data; name="model"', "", "whisper", "--b--", ""].join("\r\n");
    expect(multipartModel(utf8(raw), "b")).toBe("whisper");
    const bytes = await prepare(shapeOf(url, { method: "POST", body: raw }), new Headers({ "content-type": 'multipart/form-data; boundary="b"' }), utf8(raw), "s");
    expect(bytes.headers.get(MODEL_HEADER)).toBe("whisper");
    expect(() => multipartModel(utf8(raw.replace('name="model"', 'name="model"; filename="m"')), "b")).toThrow(ConfigurationError);
    await expect(prepare(shapeOf(url, { method: "POST", body: raw }), new Headers({ "content-type": "multipart/form-data" }), utf8(raw), "s")).rejects.toThrow(/missing its boundary/);
  });
});

describe("rank", () => {
  it("orders by rendezvous score for a prefix, moves the remembered host first, and shuffles without a prefix", async () => {
    const hosts = ["a.example", "b.example", "c.example"];
    const order = await rank(hosts, SPEC_PREFIX, undefined);
    // The order the other SDKs compute for this prefix, so a conversation lands on the same replica from any of them.
    expect(order).toEqual(["c.example", "b.example", "a.example"]);
    expect(await rank(hosts, SPEC_PREFIX, order[2])).toEqual([order[2], order[0], order[1]]);
    expect(await rank(hosts, SPEC_PREFIX, "unknown.example")).toEqual(order);
    expect([...(await rank(hosts, "", undefined))].sort()).toEqual(hosts);
  });
});

describe("GatewayTransport", () => {
  let peer: EhbpPeer;
  const MODEL = "test-model";
  const HOSTS = ["a.example", "b.example", "c.example"];

  /** A gateway that forwards sealed requests to the peer, or answers 412 naming another replica when `reroute` says so. */
  function gateway(reroute: (seal: string, enclave: string) => string | undefined = () => undefined): { fetch: Fetch; seen: { seal: string; enclave: string; model: string; prefix: string }[] } {
    const seen: { seal: string; enclave: string; model: string; prefix: string }[] = [];
    const forward = fetchOf(peer);
    return {
      seen,
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const seal = request.headers.get(SEAL_HEADER) ?? "";
        const enclave = request.headers.get("x-tinfoil-enclave-url") ?? "";
        seen.push({ seal, enclave, model: request.headers.get(MODEL_HEADER) ?? "", prefix: request.headers.get(CACHE_PREFIX_HEADER) ?? "" });
        const routed = reroute(seal, enclave);
        if (routed !== undefined) return new Response(null, { status: 412, headers: { [SEAL_HEADER]: routed } });
        return forward(request);
      },
    };
  }

  function transport(overrides: Partial<GatewayTransportConfig> & { policy: GatewayPolicy; gatewayFetch: Fetch; documentFetch?: Fetch }): GatewayTransport {
    const { gatewayFetch, ...rest } = overrides;
    return new GatewayTransport({
      baseURL: "https://gateway.example/v1/",
      relay: "gateway.example",
      catalog: () => catalogOf({ [MODEL]: { repo: "tinfoilsh/test", hosts: HOSTS } }),
      secret: "test-secret",
      documentFetch: async () => new Response(new Uint8Array([1])),
      sleep: async () => {},
      ehbp: { fetch: gatewayFetch },
      ...rest,
    });
  }

  beforeAll(async () => {
    peer = await createEhbpPeer((seen) => ({ headers: { "content-type": "application/json" }, body: JSON.stringify({ path: seen.path, sealed: seen.sealed, text: new TextDecoder().decode(seen.body) }) }));
  });

  it("refuses an upgrade before reading the catalog or touching a replica", async () => {
    let catalogReads = 0;
    const t = transport({
      policy: await GatewayPolicy.create(undefined, false, verifier(peer.publicKeyHex)),
      gatewayFetch: gateway().fetch,
      catalog: () => {
        catalogReads++;
        return catalogOf({});
      },
    });
    await expect(t.fetch("https://gateway.example/v1/realtime", { headers: { upgrade: "websocket", [MODEL_HEADER]: MODEL } })).rejects.toThrow(/protocol upgrade/);
    expect(catalogReads).toBe(0);
    await expect(t.fetch("https://gateway.example/v1/chat/completions", { method: "POST", body: '{"model":"unlisted"}', headers: { "content-type": "application/json" } })).rejects.toThrow(/no valid bare tinfoilsh\/ repository/);
    expect(catalogReads).toBe(1);
  });

  it("verifies replicas in rank order until one passes, and seals only to that one", async () => {
    const order = await rank(HOSTS, SPEC_PREFIX, undefined);
    const verified: string[] = [];
    const g = gateway();
    const t = transport({
      policy: await GatewayPolicy.create(undefined, false, verifier(peer.publicKeyHex)),
      gatewayFetch: g.fetch,
      documentFetch: async (input) => {
        const host = enclaveOf(input);
        verified.push(host);
        return host === order[2] ? new Response(new Uint8Array([1])) : new Response("no", { status: 503 });
      },
    });
    const res = await t.fetch("https://gateway.example/v1/chat/completions", { method: "POST", body: SPEC_BODY, headers: { "content-type": "application/json", authorization: "Bearer test-api-key" } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ path: "/v1/chat/completions", sealed: true });
    expect([...new Set(verified)]).toEqual(order);
    expect(g.seen).toEqual([{ seal: order[2], enclave: `https://${order[2]}`, model: MODEL, prefix: SPEC_PREFIX }]);
    const current = t.verifications();
    expect(current).toHaveLength(1);
    expect(current[0]).toMatchObject({ host: order[2], models: [MODEL], reference: "tinfoilsh/test", pinnedModel: "" });
    expect(current[0]!.verification.hpkePublicKey()).toBe(peer.publicKeyHex);
  });

  it("follows a reroute to a verified replica, remembers it for the prefix, and gives up after the limit", async () => {
    const order = await rank(HOSTS, SPEC_PREFIX, undefined);
    let reroutes = 0;
    const g = gateway((seal) => (seal === order[0] && reroutes++ < 1 ? order[1] : undefined));
    const t = transport({ policy: await GatewayPolicy.create(undefined, false, verifier(peer.publicKeyHex)), gatewayFetch: g.fetch });
    const send = () => t.fetch("https://gateway.example/v1/chat/completions", { method: "POST", body: SPEC_BODY, headers: { "content-type": "application/json", authorization: "Bearer test-api-key" } });
    expect((await send()).status).toBe(200);
    expect(g.seen.map((s) => s.seal)).toEqual([order[0], order[1]]);
    expect((await send()).status).toBe(200);
    expect(g.seen.map((s) => s.seal)).toEqual([order[0], order[1], order[1]]);

    const bouncing = gateway((seal) => HOSTS.find((h) => h !== seal));
    const forever = transport({ policy: await GatewayPolicy.create(undefined, false, verifier(peer.publicKeyHex)), gatewayFetch: bouncing.fetch });
    await expect(forever.fetch("https://gateway.example/v1/chat/completions", { method: "POST", body: SPEC_BODY, headers: { "content-type": "application/json" } })).rejects.toThrow(/kept routing away/);
    expect(bouncing.seen).toHaveLength(MAX_SEAL_REDIRECTS + 1);

    const unreplayable = transport({ policy: await GatewayPolicy.create(undefined, false, verifier(peer.publicKeyHex)), gatewayFetch: bouncing.fetch });
    const res = await unreplayable.fetch("https://gateway.example/v1/audio/transcriptions", { method: "POST", body: new Response("upload").body, duplex: "half", headers: { "content-type": "multipart/form-data; boundary=b", [MODEL_HEADER]: MODEL } } as RequestInit);
    expect(res.status).toBe(412);
  });

  it("verifies a model's replicas in a fixed order on demand and lists the models the policy serves", async () => {
    const order = await rank(HOSTS, MODEL, undefined);
    const attempts: string[] = [];
    const repos: string[] = [];
    const t = transport({
      policy: await GatewayPolicy.create(new Map([[MODEL, { repo: "tinfoilsh/test@v1" }], ["unlisted", { repo: "tinfoilsh/unlisted" }]]), false, verifier(peer.publicKeyHex, false, repos)),
      gatewayFetch: gateway().fetch,
      catalog: () => catalogOf({ [MODEL]: { repo: "tinfoilsh/test", hosts: HOSTS }, other: { repo: "tinfoilsh/other", hosts: ["o.example"] } }),
      documentFetch: async (input) => {
        const host = enclaveOf(input);
        attempts.push(host);
        return host === order[1] ? new Response(new Uint8Array([1])) : new Response("no", { status: 503 });
      },
    });
    expect(await t.models()).toEqual(["other", MODEL]);
    const v = await t.ensureVerified(MODEL);
    expect(v.hpkePublicKey()).toBe(peer.publicKeyHex);
    expect([...new Set(attempts)]).toEqual([order[0], order[1]]);
    expect(repos).toEqual(["tinfoilsh/test@v1"]);
    await t.ensureVerified(MODEL);
    expect(repos).toHaveLength(1);
    expect(t.verifications()[0]).toMatchObject({ host: order[1], reference: "tinfoilsh/test@v1", pinnedModel: MODEL, models: [] });
    await expect(t.ensureVerified("unlisted")).rejects.toBeInstanceOf(ConfigurationError);
    const aborted = new AbortController();
    aborted.abort(new Error("stop"));
    await expect(t.ensureVerified("other", aborted.signal)).rejects.toThrow(/stop/);
  });

  it("replays once after a replica rotates its key, naming the replica on every attempt", async () => {
    const stale = await (await Identity.generate()).getPublicKeyHex();
    let verifications = 0;
    const rotating = verifier(peer.publicKeyHex);
    const flaky = { ...rotating, verifyV3At: (...args: unknown[]) => (verifier(verifications++ === 0 ? stale : peer.publicKeyHex).verifyV3At as (...a: unknown[]) => Promise<Verification>)(...args) } as Verifier;
    const g = gateway();
    const t = transport({ policy: await GatewayPolicy.create(undefined, false, flaky), gatewayFetch: g.fetch, catalog: () => catalogOf({ [MODEL]: { repo: "tinfoilsh/test", hosts: ["only.example"] } }) });
    const res = await t.fetch("https://gateway.example/v1/chat/completions", { method: "POST", body: '{"model":"test-model"}', headers: { "content-type": "application/json" } });
    expect(res.status).toBe(200);
    expect(verifications).toBe(2);
    expect(g.seen.map((s) => s.enclave)).toEqual(["https://only.example", "https://only.example"]);
  });
});
