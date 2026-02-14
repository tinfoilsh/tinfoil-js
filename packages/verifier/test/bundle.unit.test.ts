import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { FetchError, AttestationError } from "../src/errors.js";

/**
 * Unit tests for assembleAttestationBundle with mocked fetch.
 * Tests the retry logic (withRetry) and error handling
 * without making real network requests.
 *
 * Uses fake timers to skip backoff delays (500ms, 1s, 2s).
 */

// Track calls per URL to simulate transient failures
let fetchCallsByUrl: Map<string, number>;

beforeEach(() => {
  fetchCallsByUrl = new Map();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

/** Create a mock fetch that fails N times for a given URL pattern, then succeeds. */
function createMockFetch(
  failuresPerPattern: Record<string, number>,
  responseMap: Record<string, () => Response>,
) {
  return vi.fn(async (url: string) => {
    const count = (fetchCallsByUrl.get(url) ?? 0) + 1;
    fetchCallsByUrl.set(url, count);

    // Check if this URL should fail
    for (const [pattern, maxFailures] of Object.entries(failuresPerPattern)) {
      if (url.includes(pattern) && count <= maxFailures) {
        throw new TypeError(`Network error for ${url}`);
      }
    }

    // Find matching response
    for (const [pattern, responseFn] of Object.entries(responseMap)) {
      if (url.includes(pattern)) {
        return responseFn();
      }
    }
    return new Response("Not Found", { status: 404 });
  });
}

function jsonResponse(body: any) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function textResponse(body: string) {
  return new Response(body, { status: 200, headers: { "Content-Type": "text/plain" } });
}

function binaryResponse(data: Uint8Array) {
  return new Response(data, { status: 200, headers: { "Content-Type": "application/octet-stream" } });
}

/** Flush all pending backoff timers by advancing time in steps. */
async function flushRetryBackoffs() {
  // withRetry backoffs: 500ms * 2^0, 500ms * 2^1, 500ms * 2^2 = 500, 1000, 2000
  // Advance enough to cover all possible backoff delays
  for (let i = 0; i < 5; i++) {
    await vi.advanceTimersByTimeAsync(2000);
  }
}

describe("assembleAttestationBundle — retry logic", () => {
  // We can't easily import the private withRetry directly, so we test it
  // indirectly through assembleAttestationBundle by mocking global fetch.

  it("should retry on transient network failure and succeed", async () => {
    // Attestation endpoint fails once, then succeeds
    const mockFetch = createMockFetch(
      { "tinfoil-attestation": 1 }, // fail 1st call to attestation endpoint
      {
        "tinfoil-attestation": () => jsonResponse({ format: "sev-snp-guest/v2", body: "dGVzdA==" }),
        "tinfoil-certificate": () => jsonResponse({ certificate: "mock-cert" }),
        "releases/latest": () => jsonResponse({ tag_name: "v1.0" }),
        "tinfoil.hash": () => textResponse("abc123"),
        "attestations/sha256": () => jsonResponse({ attestations: [{ bundle: { mock: true } }] }),
        "kds-proxy": () => binaryResponse(new Uint8Array([1, 2, 3])),
      },
    );

    vi.stubGlobal("fetch", mockFetch);

    const { assembleAttestationBundle } = await import("../src/bundle.js");

    // Start the bundle assembly (will hit retry backoff)
    const promise = assembleAttestationBundle("test-enclave.com", "test-org/test-repo")
      .catch(() => {}); // Expected — mock data won't parse as real attestation report

    // Flush all backoff timers
    await flushRetryBackoffs();
    await promise;

    // The attestation endpoint should have been called twice (1 failure + 1 retry)
    const attestationCalls = fetchCallsByUrl.get(
      "https://test-enclave.com/.well-known/tinfoil-attestation"
    );
    expect(attestationCalls).toBe(2);
  });

  it("should give up after MAX_RETRIES (2) failures", async () => {
    // Attestation endpoint always fails
    const mockFetch = vi.fn(async (url: string) => {
      if (url.includes("tinfoil-attestation")) {
        throw new TypeError("Network error");
      }
      // Other endpoints succeed but won't be reached since they run in parallel
      return jsonResponse({});
    });

    vi.stubGlobal("fetch", mockFetch);

    const { assembleAttestationBundle } = await import("../src/bundle.js");

    // Start the bundle assembly and attach assertion before advancing timers
    const assertion = expect(
      assembleAttestationBundle("test-enclave.com", "test-org/test-repo"),
    ).rejects.toThrow(FetchError);

    // Flush all backoff timers
    await flushRetryBackoffs();
    await assertion;

    // Should have tried 3 times total (initial + 2 retries)
    const attestationCalls = mockFetch.mock.calls.filter(
      ([url]: [string]) => url.includes("tinfoil-attestation"),
    );
    expect(attestationCalls.length).toBe(3);
  });

  it("should not retry on non-FetchError", async () => {
    // Return a response that will cause a parse error (not a FetchError)
    const mockFetch = vi.fn(async (url: string) => {
      if (url.includes("tinfoil-attestation")) {
        return jsonResponse({ format: "sev-snp-guest/v2", body: "not-valid-base64!!!" });
      }
      if (url.includes("releases/latest")) {
        return jsonResponse({ tag_name: "v1.0" });
      }
      if (url.includes("tinfoil.hash")) {
        return textResponse("abc123");
      }
      if (url.includes("tinfoil-certificate")) {
        return jsonResponse({ certificate: "mock-cert" });
      }
      if (url.includes("attestations/sha256")) {
        return jsonResponse({ attestations: [{ bundle: { mock: true } }] });
      }
      return new Response("Not Found", { status: 404 });
    });

    vi.stubGlobal("fetch", mockFetch);

    const { assembleAttestationBundle } = await import("../src/bundle.js");

    // Should throw immediately (no retry on parse errors) — no timers to flush
    await expect(
      assembleAttestationBundle("test-enclave.com", "test-org/test-repo"),
    ).rejects.toThrow();

    // Attestation endpoint called only once (no retry on parse errors)
    const attestationCalls = mockFetch.mock.calls.filter(
      ([url]: [string]) => url.includes("tinfoil-attestation"),
    );
    expect(attestationCalls.length).toBe(1);
  });

  it("should throw FetchError on HTTP 500", async () => {
    const mockFetch = vi.fn(async (url: string) => {
      if (url.includes("tinfoil-attestation")) {
        return new Response("Internal Server Error", { status: 500 });
      }
      return jsonResponse({});
    });

    vi.stubGlobal("fetch", mockFetch);

    const { assembleAttestationBundle } = await import("../src/bundle.js");

    const assertion = expect(
      assembleAttestationBundle("test-enclave.com", "test-org/test-repo"),
    ).rejects.toThrow(FetchError);

    await flushRetryBackoffs();
    await assertion;
  });
});
