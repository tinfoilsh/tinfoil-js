/**
 * Fetching an attestation document: the request it sends, the redirects it
 * follows and refuses, the size cap, and how failures are classified.
 */
import { describe, expect, it } from "vitest";
import { ConfigurationError, NetworkError } from "../../src/v3/errors.js";
import { attestationURL, fetchDocument, isAuthority, MAX_ATTESTATION_BYTES, SDK_NAME_HEADER, SDK_VERSION_HEADER } from "../../src/v3/internal/fetch.js";
import type { Fetch } from "../../src/v3/options.js";
import { SDK_NAME, SDK_VERSION } from "../../src/version.js";

const nonce = new Uint8Array(32).fill(0xab);
const nonceHex = "ab".repeat(32);

interface Call {
  url: string;
  init: RequestInit | undefined;
}

/** A fetch that answers each URL from `routes` and records what it was asked. */
function routed(routes: Record<string, () => Response>): { fetch: Fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetch: Fetch = async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    calls.push({ url, init });
    const route = routes[url];
    if (route === undefined) throw new Error(`unexpected request ${url}`);
    return route();
  };
  return { fetch, calls };
}

describe("attestationURL", () => {
  it("names the enclave's endpoint with the nonce, or a relay with the enclave as a query", () => {
    expect(attestationURL("enclave.example", undefined, nonce)).toBe(`https://enclave.example/.well-known/tinfoil-attestation?nonce=${nonceHex}`);
    expect(attestationURL("enclave.example:8443", "", nonce)).toBe(`https://enclave.example:8443/.well-known/tinfoil-attestation?nonce=${nonceHex}`);
    expect(attestationURL("enclave.example", "relay.example", nonce)).toBe(
      `https://relay.example/.well-known/tinfoil-attestation?nonce=${nonceHex}&enclave=enclave.example`,
    );
  });

  it("rejects a missing host, a host that is not a bare authority, and a nonce of the wrong size", () => {
    expect(() => attestationURL("", undefined, nonce)).toThrow(ConfigurationError);
    for (const bad of ["https://enclave.example", "enclave.example/path", "user@enclave.example", "enclave.example?x=1", "a b"]) {
      expect(() => attestationURL(bad, undefined, nonce), bad).toThrow(ConfigurationError);
      expect(() => attestationURL("enclave.example", bad, nonce), bad).toThrow(ConfigurationError);
    }
    expect(() => attestationURL("enclave.example", undefined, new Uint8Array(16))).toThrow(/nonce must be 32 bytes/);
  });
});

describe("isAuthority", () => {
  it("accepts hosts with an optional port, including IPv6 and an explicit default port", () => {
    for (const ok of ["enclave.example", "enclave.example:8443", "enclave.example:443", "10.0.0.1:9000", "[::1]:8443", "localhost"]) {
      expect(isAuthority(ok), ok).toBe(true);
    }
    for (const bad of ["", "https://x", "x/", "x?y", "u@x", "x#f", "x:y"]) expect(isAuthority(bad), bad).toBe(false);
  });
});

describe("fetchDocument", () => {
  const endpoint = `https://enclave.example/.well-known/tinfoil-attestation?nonce=${nonceHex}`;

  it("sends a GET with the SDK headers and manual redirects, and returns the body", async () => {
    const { fetch, calls } = routed({ [endpoint]: () => new Response(new Uint8Array([1, 2, 3])) });
    expect(await fetchDocument("enclave.example", undefined, nonce, fetch)).toEqual(new Uint8Array([1, 2, 3]));
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init?.method).toBe("GET");
    expect(calls[0]!.init?.redirect).toBe("manual");
    expect(calls[0]!.init?.headers).toEqual({ [SDK_NAME_HEADER]: SDK_NAME, [SDK_VERSION_HEADER]: SDK_VERSION });
    expect(calls[0]!.init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("follows an HTTPS redirect and refuses one to another scheme", async () => {
    const moved = `https://other.example/doc?nonce=${nonceHex}`;
    const { fetch, calls } = routed({
      [endpoint]: () => new Response(null, { status: 302, headers: { location: moved } }),
      [moved]: () => new Response(new Uint8Array([9])),
    });
    expect(await fetchDocument("enclave.example", undefined, nonce, fetch)).toEqual(new Uint8Array([9]));
    expect(calls.map((c) => c.url)).toEqual([endpoint, moved]);

    const insecure = routed({ [endpoint]: () => new Response(null, { status: 302, headers: { location: "http://other.example/doc" } }) });
    await expect(fetchDocument("enclave.example", undefined, nonce, insecure.fetch)).rejects.toThrow(/refusing redirect to non-HTTPS URL/);
    await expect(fetchDocument("enclave.example", undefined, nonce, insecure.fetch)).rejects.toBeInstanceOf(NetworkError);

    const silent = routed({ [endpoint]: () => new Response(null, { status: 302 }) });
    await expect(fetchDocument("enclave.example", undefined, nonce, silent.fetch)).rejects.toThrow(/without a Location header/);
  });

  it("stops after ten redirects", async () => {
    const loop: Fetch = async () => new Response(null, { status: 307, headers: { location: endpoint } });
    await expect(fetchDocument("enclave.example", undefined, nonce, loop)).rejects.toThrow(/stopped after 10 redirects/);
  });

  it("reports an error status as a network error", async () => {
    const { fetch } = routed({ [endpoint]: () => new Response("busy", { status: 503, statusText: "Service Unavailable" }) });
    const err = await fetchDocument("enclave.example", undefined, nonce, fetch).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as Error).message).toBe(`network error: HTTP GET ${endpoint}: 503 Service Unavailable`);
  });

  it("caps the document while it streams", async () => {
    const chunk = new Uint8Array(1 << 20);
    let served = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        served += chunk.length;
        controller.enqueue(chunk);
      },
    });
    const { fetch } = routed({ [endpoint]: () => new Response(body) });
    await expect(fetchDocument("enclave.example", undefined, nonce, fetch)).rejects.toThrow(/attestation document exceeds/);
    expect(served).toBeLessThan(MAX_ATTESTATION_BYTES + 4 * chunk.length);
  });

  it("wraps a failed request as a network error and treats a hidden redirect as one", async () => {
    const down: Fetch = async () => {
      throw new TypeError("fetch failed");
    };
    const err = await fetchDocument("enclave.example", undefined, nonce, down).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as Error).cause).toBeInstanceOf(TypeError);

    const opaque: Fetch = async () => Object.defineProperty(new Response(null, { status: 200 }), "type", { value: "opaqueredirect" });
    await expect(fetchDocument("enclave.example", undefined, nonce, opaque)).rejects.toThrow(/redirected, which this runtime does not follow/);
  });

  it("passes a caller's signal through and rejects once it aborts", async () => {
    const controller = new AbortController();
    controller.abort(new Error("caller gave up"));
    const { fetch, calls } = routed({ [endpoint]: () => new Response(new Uint8Array([1])) });
    const guarded: Fetch = async (input, init) => {
      init?.signal?.throwIfAborted();
      return fetch(input, init);
    };
    await expect(fetchDocument("enclave.example", undefined, nonce, guarded, controller.signal)).rejects.toThrow(/caller gave up/);
    expect(calls).toHaveLength(0);
  });
});
