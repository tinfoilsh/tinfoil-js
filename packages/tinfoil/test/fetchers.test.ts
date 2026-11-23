/**
 * The attestation and router-list fetchers: the relay protocol's URLs,
 * headers, parsing and URL checks, and the clients' use of a caller's
 * fetchers for every verification and for discovery, with their errors in
 * the client's categories.
 */
import { describe, expect, it } from "vitest";
import { createEnclaveHTTPClient } from "../src/enclave-client.js";
import { AttestationError, ConfigurationError, NetworkError } from "../src/errors.js";
import { attestationRelay, routerListRelay } from "../src/fetchers.js";
import type { AttestationFetcher, Fetch, RouterListFetcher } from "../src/options.js";
import { createRouterHTTPClient } from "../src/router-client.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, type VerificationReport, type VerifiedFacts, type Verifier } from "../../verifier/src/index.js";
import { verifiedReport } from "./helpers/report.js";

const NONCE = new Uint8Array(32).fill(0xab);
const NONCE_HEX = "ab".repeat(32);
const TLS_KEY = "cd".repeat(32);

/** A fetch that records each request and answers with `respond`. */
function recording(respond: (url: string) => Response = () => new Response(new Uint8Array([1]))): { fetch: Fetch; seen: Request[] } {
  const seen: Request[] = [];
  return {
    seen,
    fetch: async (input, init) => {
      const request = new Request(input, init);
      seen.push(request);
      return respond(request.url);
    },
  };
}

/** A verifier that endorses a TLS key for every document except one that starts with "bad", recording the documents in `seenDocs`. */
function verifier(seenDocs: string[] = [], expiresAt: () => Date = () => new Date(Date.now() + 60_000)): Verifier {
  return {
    checkPinVerifiability: () => undefined,
    verifyV3At: async (doc: Uint8Array) => {
      const text = new TextDecoder().decode(doc);
      seenDocs.push(text);
      if (text.startsWith("bad")) throw new Error("rejected document");
      return verifiedReport({
        cryptoMaterial: [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: TLS_KEY }],
        tlsPublicKeyFP: TLS_KEY,
        codeDigest: "11".repeat(32),
        freshnessExpiresAt: expiresAt(),
      });
    },
  } as unknown as Verifier;
}

/** A fetch that fails the test if it is called: nothing may be fetched directly. */
const forbidden: Fetch = async (input) => {
  throw new Error(`fetched directly: ${String(input)}`);
};

describe("attestationRelay", () => {
  it.each([
    ["https://app.example/tinfoil", "https://app.example/tinfoil/.well-known/tinfoil-attestation"],
    ["https://app.example/tinfoil/", "https://app.example/tinfoil/.well-known/tinfoil-attestation"],
    ["https://app.example", "https://app.example/.well-known/tinfoil-attestation"],
    ["https://app.example:8443/a/b", "https://app.example:8443/a/b/.well-known/tinfoil-attestation"],
    ["http://localhost:8080/tinfoil", "http://localhost:8080/tinfoil/.well-known/tinfoil-attestation"],
  ])("joins the request path under %s", async (url, want) => {
    const net = recording();
    const doc = await attestationRelay(url, { fetch: net.fetch })("enclave.example", NONCE, { signal: new AbortController().signal });
    expect(doc).toEqual(new Uint8Array([1]));
    expect(net.seen[0]!.url).toBe(`${want}?nonce=${NONCE_HEX}&enclave=enclave.example`);
  });

  it("encodes a host with a port, sends the SDK identity headers and nothing that identifies the caller", async () => {
    const net = recording();
    await attestationRelay("https://app.example", { fetch: net.fetch })("enclave.example:8443", NONCE, { signal: new AbortController().signal });
    const request = net.seen[0]!;
    expect(new URL(request.url).search).toBe(`?nonce=${NONCE_HEX}&enclave=enclave.example%3A8443`);
    expect(request.method).toBe("GET");
    expect(request.headers.get("tinfoil-sdk")).toBeTruthy();
    expect(request.headers.get("tinfoil-sdk-version")).toBeTruthy();
    expect(request.headers.has("authorization")).toBe(false);
  });

  it("reports an error status, an unreachable relay and a redirect to plaintext as a network error", async () => {
    const signal = new AbortController().signal;
    const failing = [
      recording(() => new Response("nope", { status: 502 })).fetch,
      (async () => {
        throw new TypeError("fetch failed");
      }) as Fetch,
      recording(() => new Response(null, { status: 302, headers: { location: "http://app.example/doc" } })).fetch,
    ];
    for (const fetch of failing) {
      const err = await attestationRelay("https://app.example", { fetch })("enclave.example", NONCE, { signal }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(NetworkError);
      expect((err as Error).cause).toBeDefined();
    }
  });

  it("refuses a URL that breaks the route URL rules when it is built, before any network I/O", () => {
    for (const url of [
      "http://app.example/tinfoil",
      "http://0.0.0.0/tinfoil",
      "/tinfoil",
      "app.example",
      "ftp://app.example/",
      "https://user:pw@app.example/",
      "https://app.example/?",
      "https://app.example/?a=1",
      "https://app.example/#",
      "https://app.example/#f",
      "",
      7 as unknown as string,
    ]) {
      expect(() => attestationRelay(url), String(url)).toThrow(ConfigurationError);
      expect(() => routerListRelay(url), String(url)).toThrow(ConfigurationError);
    }
    expect(() => attestationRelay("http://127.0.0.1:8080/tinfoil")).not.toThrow();
    expect(() => routerListRelay("http://[::1]:8080/tinfoil")).not.toThrow();
  });
});

describe("routerListRelay", () => {
  it.each([
    ["https://app.example/tinfoil", "https://app.example/tinfoil/routers"],
    ["https://app.example/tinfoil/", "https://app.example/tinfoil/routers"],
    ["https://app.example", "https://app.example/routers"],
  ])("fetches the list from under %s", async (url, want) => {
    const net = recording(() => new Response(JSON.stringify(["router.example"])));
    expect(await routerListRelay(url, { fetch: net.fetch })({ signal: new AbortController().signal })).toEqual(["router.example"]);
    expect(net.seen[0]!.url).toBe(want);
  });

  it("parses the response as Tinfoil's list is parsed", async () => {
    const signal = new AbortController().signal;
    for (const body of ['{"routers":[]}', "[1,2]", "not json"]) {
      const net = recording(() => new Response(body));
      await expect(routerListRelay("https://app.example", { fetch: net.fetch })({ signal })).rejects.toBeInstanceOf(NetworkError);
    }
  });
});

describe("an enclave client with fetchAttestation", () => {
  it("obtains every document through it, nothing directly, and verifies each one", async () => {
    const calls: { host: string; nonce: Uint8Array }[] = [];
    const fetchAttestation: AttestationFetcher = async (host, nonce, { signal }) => {
      expect(signal).toBeInstanceOf(AbortSignal);
      calls.push({ host, nonce });
      return new TextEncoder().encode(`doc ${calls.length}`);
    };
    const docs: string[] = [];
    const client = await createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "o/r" }, { transport: { kind: "tls" }, fetchAttestation }, { documentFetch: forbidden, verifier: verifier(docs) });
    await client.reverify();
    expect(calls.map((c) => c.host)).toEqual(["enclave.example", "enclave.example"]);
    expect(calls.every((c) => c.nonce.length === 32)).toBe(true);
    expect(docs).toEqual(["doc 1", "doc 2"]);
    await client.close();
  });

  it("works through a relay helper", async () => {
    const net = recording(() => new Response("doc"));
    const client = await createEnclaveHTTPClient(
      "enclave.example:8443",
      { kind: "repoPin", repo: "o/r" },
      { transport: { kind: "tls" }, fetchAttestation: attestationRelay("https://app.example/tinfoil", { fetch: net.fetch }) },
      { documentFetch: forbidden, verifier: verifier() },
    );
    expect(net.seen[0]!.url).toMatch(/^https:\/\/app\.example\/tinfoil\/\.well-known\/tinfoil-attestation\?nonce=[0-9a-f]{64}&enclave=enclave\.example%3A8443$/);
    await client.close();
  });

  it("reports a callback's error as a network error, keeps an SDK error's category, and doesn't retry a configuration error", async () => {
    const create = (fetchAttestation: AttestationFetcher) =>
      createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "o/r" }, { transport: { kind: "tls" }, fetchAttestation }, { documentFetch: forbidden, verifier: verifier(), sleep: async () => {} });
    const plain = new Error("relay down");
    const err = await create(async () => {
      throw plain;
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as Error).cause).toBe(plain);
    await expect(create(async () => Promise.reject(new AttestationError("refused")))).rejects.toBeInstanceOf(AttestationError);
    let configurationCalls = 0;
    await expect(
      create(async () => {
        configurationCalls++;
        throw new ConfigurationError("misconfigured relay");
      }),
    ).rejects.toBeInstanceOf(ConfigurationError);
    expect(configurationCalls).toBe(1);
    await expect(create(async () => "not bytes" as unknown as Uint8Array)).rejects.toThrow(/must resolve to a Uint8Array/);
  });

  it("reports a document that fails verification as an attestation error", async () => {
    await expect(
      createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "o/r" }, { transport: { kind: "tls" }, fetchAttestation: async () => new TextEncoder().encode("bad doc") }, { documentFetch: forbidden, verifier: verifier(), sleep: async () => {} }),
    ).rejects.toBeInstanceOf(AttestationError);
    // The real verifier refuses a document that doesn't answer the nonce.
    await expect(
      createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "tls" }, fetchAttestation: async () => new TextEncoder().encode("{}") }, { documentFetch: forbidden, sleep: async () => {} }),
    ).rejects.toBeInstanceOf(AttestationError);
  });

  it("passes the caller's cancellation through, even from a callback that ignores its signal", async () => {
    const controller = new AbortController();
    const reason = new Error("gave up");
    const pending = createEnclaveHTTPClient(
      "enclave.example",
      { kind: "repoPin", repo: "o/r" },
      { transport: { kind: "tls" }, signal: controller.signal, fetchAttestation: () => new Promise<Uint8Array>(() => {}) },
      { documentFetch: forbidden, verifier: verifier() },
    );
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });

  it("refuses a fetcher that isn't a function before any network I/O", async () => {
    await expect(createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "o/r" }, { fetchAttestation: "https://app.example" as never }, { documentFetch: forbidden })).rejects.toBeInstanceOf(ConfigurationError);
    await expect(createRouterHTTPClient({ fetchRouterList: "https://app.example" as never }, { documentFetch: forbidden, routersFetch: forbidden })).rejects.toBeInstanceOf(ConfigurationError);
  });
});

describe("a router client with fetchAttestation and fetchRouterList", () => {
  it("uses the caller's list and fetcher for each candidate and the fallback, fetching nothing directly", async () => {
    const hosts: string[] = [];
    const fetchAttestation: AttestationFetcher = async (host) => {
      hosts.push(host);
      return new TextEncoder().encode(host.startsWith("bad") ? "bad" : "good");
    };
    const list = Object.freeze(["bad-a.example", "bad-b.example"]);
    const fetchRouterList: RouterListFetcher = async () => list;
    const client = await createRouterHTTPClient({ transport: { kind: "tls" }, fetchAttestation, fetchRouterList }, { documentFetch: forbidden, routersFetch: forbidden, verifier: verifier() });
    // Both candidates fail, in either order, and the fallback is verified through the fetcher too.
    expect([...hosts].sort()).toEqual(["bad-a.example", "bad-b.example", "inference.tinfoil.sh"]);
    expect(hosts[2]).toBe("inference.tinfoil.sh");
    expect(client.enclave).toBe("inference.tinfoil.sh");
    // The caller's list is untouched: it is frozen, so a shuffle in place would have thrown.
    expect(list).toEqual(["bad-a.example", "bad-b.example"]);
    await client.close();
  });

  it("takes a failing or malformed list as empty and falls back, without fetching Tinfoil's list", async () => {
    for (const fetchRouterList of [
      (async () => {
        throw new Error("relay down");
      }) as RouterListFetcher,
      (async () => "router.example") as unknown as RouterListFetcher,
      (async () => [1, 2]) as unknown as RouterListFetcher,
    ]) {
      const hosts: string[] = [];
      const client = await createRouterHTTPClient(
        { transport: { kind: "tls" }, fetchRouterList, fetchAttestation: async (host) => (hosts.push(host), new TextEncoder().encode("good")) },
        { documentFetch: forbidden, routersFetch: forbidden, verifier: verifier() },
      );
      expect(hosts).toEqual(["inference.tinfoil.sh"]);
      await client.close();
    }
  });

  it("shuffles a copy of the list, so that clients spread across routers", async () => {
    const list = Array.from({ length: 8 }, (_, i) => `r${i}.example`);
    const firsts = new Set<string>();
    for (let i = 0; i < 40; i++) {
      const hosts: string[] = [];
      const client = await createRouterHTTPClient(
        { transport: { kind: "tls" }, fetchRouterList: async () => list, fetchAttestation: async (host) => (hosts.push(host), new TextEncoder().encode("good")) },
        { documentFetch: forbidden, routersFetch: forbidden, verifier: verifier() },
      );
      firsts.add(hosts[0]!);
      await client.close();
    }
    expect(firsts.size).toBeGreaterThan(1);
    expect(list).toEqual(Array.from({ length: 8 }, (_, i) => `r${i}.example`));
  });

  it("passes the caller's cancellation through while the list is fetched, without falling back", async () => {
    const controller = new AbortController();
    const reason = new Error("gave up");
    let attested = 0;
    const pending = createRouterHTTPClient(
      { transport: { kind: "tls" }, signal: controller.signal, fetchRouterList: () => new Promise<readonly string[]>(() => {}), fetchAttestation: async () => (attested++, new TextEncoder().encode("good")) },
      { documentFetch: forbidden, routersFetch: forbidden, verifier: verifier() },
    );
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
    expect(attested).toBe(0);
  });

  it("relays both through helpers on one origin, with discovery still running", async () => {
    const net = recording((url) => (url.endsWith("/routers") ? new Response(JSON.stringify(["router.example"])) : new Response("good")));
    const client = await createRouterHTTPClient(
      {
        transport: { kind: "ehbp", proxyURL: "https://app.example/proxy" },
        fetchAttestation: attestationRelay("https://app.example/tinfoil", { fetch: net.fetch }),
        fetchRouterList: routerListRelay("https://app.example/tinfoil", { fetch: net.fetch }),
      },
      { documentFetch: forbidden, routersFetch: forbidden, verifier: verifierWithHPKE() },
    );
    expect(net.seen.map((r) => new URL(r.url).pathname)).toEqual(["/tinfoil/routers", "/tinfoil/.well-known/tinfoil-attestation"]);
    expect(client.enclave).toBe("router.example");
    expect(client.baseURL).toBe("https://app.example/proxy/");
    await client.close();
  });
});

/** As {@link verifier}, with an HPKE key, which the EHBP transport needs. */
function verifierWithHPKE(): Verifier {
  const base = verifier();
  return {
    ...base,
    verifyV3At: async (...args: Parameters<Verifier["verifyV3At"]>) => {
      const v = (await base.verifyV3At(...args)).verifiedFacts as unknown as Record<string, unknown>;
      const hpke = "ef".repeat(32);
      return verifiedReport({ ...v, hpkePublicKey: hpke, cryptoMaterial: [...(v.cryptoMaterial as object[]), { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke }] });
    },
  } as unknown as Verifier;
}
