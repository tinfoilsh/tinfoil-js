/**
 * Router discovery with a mocked router list and attestation documents:
 * the order routers are tried in, the fallback, the time budget, and the
 * failures that stop discovery instead of moving it on.
 */
import { describe, expect, it } from "vitest";
import { ConfigurationError } from "../src/errors.js";
import { DEFAULT_ROUTER_URL, discoverRouter, FALLBACK_ROUTER_HOST, fetchRouters, MAX_ROUTER_BYTES, type DiscoveryConfig } from "../src/internal/router.js";
import { tlsMode } from "../src/internal/transport/tls.js";
import type { Fetch } from "../src/options.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, UsageError, type Verification, type Verifier } from "../../verifier/src/index.js";

const PIN = "ab".repeat(32);

/** A verifier that accepts every document, recording the repo it was asked to verify. */
function verifier(repos: string[] = []): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo === "") throw new UsageError("repo required");
    },
    callerAuthorizesConfig: false,
    verifyV3At: async (_doc: Uint8Array, _nonce: Uint8Array, repo: string) => {
      repos.push(repo);
      const material = [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: PIN }];
      return {
        cryptoMaterial: material.map((m) => ({ ...m })),
        tlsPublicKeyFP: PIN,
        hpkePublicKey: undefined,
        codeDigest: "11".repeat(32),
        freshnessExpiresAt: new Date(Date.now() + 60_000),
      } as unknown as Verification;
    },
  } as unknown as Verifier;
}

/** Attestation documents for every host but `failing`, recording the hosts asked in order. */
function documents(failing: string[] = []): { fetch: Fetch; hosts: string[] } {
  const hosts: string[] = [];
  return {
    hosts,
    fetch: async (input) => {
      const host = new URL(String(input)).host;
      hosts.push(host);
      if (failing.includes(host)) return new Response("unavailable", { status: 503 });
      return new Response(new Uint8Array([1]));
    },
  };
}

function routerList(body: unknown, status = 200): { fetch: Fetch; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetch: async (input) => {
      calls.push(String(input));
      return new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
    },
  };
}

function config(overrides: Partial<DiscoveryConfig>): DiscoveryConfig {
  return { verifier: verifier(), mode: tlsMode(), sleep: async () => {}, ...overrides };
}

describe("discoverRouter", () => {
  it("tries routers in list order and keeps the first that verifies, already verified", async () => {
    const docs = documents(["r1.example"]);
    const list = routerList(["r1.example", "r2.example", "r3.example"]);
    const repos: string[] = [];
    const transport = await discoverRouter(config({ verifier: verifier(repos), routersFetch: list.fetch, documentFetch: docs.fetch }));
    expect(list.calls).toEqual([DEFAULT_ROUTER_URL]);
    expect(transport.enclave().host()).toBe("r2.example");
    expect(transport.enclave().repo()).toBe("tinfoilsh/confidential-model-router");
    expect(transport.current()?.tlsPublicKeyFP).toBe(PIN);
    expect(docs.hosts.filter((h) => h !== "r1.example")).toEqual(["r2.example"]);
    expect(docs.hosts[0]).toBe("r1.example");
    expect(repos).toEqual(["tinfoilsh/confidential-model-router"]);
  });

  it("moves past a router the verification check rejects", async () => {
    const docs = documents();
    let checks = 0;
    const transport = await discoverRouter(
      config({
        routersFetch: routerList(["r1.example", "r2.example"]).fetch,
        documentFetch: docs.fetch,
        verificationCheck: () => {
          if (checks++ === 0) throw new Error("not this one");
        },
      }),
    );
    expect(transport.enclave().host()).toBe("r2.example");
  });

  it("falls back to the default router, unverified, when no router verifies", async () => {
    const docs = documents(["r1.example", "r2.example"]);
    const transport = await discoverRouter(config({ routersFetch: routerList(["r1.example", "r2.example"]).fetch, documentFetch: docs.fetch }));
    expect(transport.enclave().host()).toBe(FALLBACK_ROUTER_HOST);
    expect(transport.current()).toBeUndefined();
    expect(docs.hosts).not.toContain(FALLBACK_ROUTER_HOST);
  });

  it("falls back when the router list is unavailable or malformed", async () => {
    const lists: Fetch[] = [
      routerList("down", 500).fetch,
      routerList("not json").fetch,
      routerList({ routers: [] }).fetch,
      routerList([1, 2]).fetch,
      routerList([]).fetch,
      async () => {
        throw new TypeError("fetch failed");
      },
      async () => new Response(null, { status: 302, headers: { location: "http://atc.tinfoil.sh/routers" } }),
    ];
    for (const routersFetch of lists) {
      const docs = documents();
      const transport = await discoverRouter(config({ routersFetch, documentFetch: docs.fetch }));
      expect(transport.enclave().host()).toBe(FALLBACK_ROUTER_HOST);
      expect(docs.hosts).toEqual([]);
    }
  });

  it("stops trying routers once the discovery budget is spent", async () => {
    let now = Date.parse("2026-11-04T00:00:00Z");
    const docs = documents(["r1.example"]);
    const fetch: Fetch = async (input, init) => {
      now += 31_000;
      return docs.fetch(input, init);
    };
    const transport = await discoverRouter(
      config({ routersFetch: routerList(["r1.example", "r2.example"]).fetch, documentFetch: fetch, clock: () => new Date(now) }),
    );
    expect(transport.enclave().host()).toBe(FALLBACK_ROUTER_HOST);
    expect(docs.hosts).not.toContain("r2.example");
  });

  it("stops with a configuration error before fetching anything when the policy is unusable", async () => {
    const list = routerList(["r1.example"]);
    const broken = { ...verifier(), checkRepoVerifiability: () => {
      throw new UsageError("unusable policy");
    } } as unknown as Verifier;
    await expect(discoverRouter(config({ verifier: broken, routersFetch: list.fetch }))).rejects.toBeInstanceOf(ConfigurationError);
    expect(list.calls).toEqual([]);
  });

  it("ends when the caller's signal aborts instead of falling back", async () => {
    const controller = new AbortController();
    const list: Fetch = async () => {
      controller.abort(new Error("caller gave up"));
      return new Response(JSON.stringify(["r1.example"]));
    };
    await expect(discoverRouter(config({ routersFetch: list, documentFetch: documents().fetch, signal: controller.signal }))).rejects.toThrow(/caller gave up/);
  });
});

describe("fetchRouters", () => {
  it("rejects a list larger than its cap", async () => {
    const huge = new Uint8Array(MAX_ROUTER_BYTES + 1).fill(0x20);
    await expect(fetchRouters(async () => new Response(huge))).rejects.toThrow(/exceeds/);
  });

  it("follows an HTTPS redirect", async () => {
    const calls: string[] = [];
    const routers = await fetchRouters(async (input) => {
      calls.push(String(input));
      return calls.length === 1
        ? new Response(null, { status: 307, headers: { location: "https://atc.tinfoil.sh/routers/v2" } })
        : new Response(JSON.stringify(["r1.example"]));
    });
    expect(routers).toEqual(["r1.example"]);
    expect(calls).toEqual([DEFAULT_ROUTER_URL, "https://atc.tinfoil.sh/routers/v2"]);
  });
});
