import { describe, it, expect, vi, beforeEach } from "vitest";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v1";

const mockVerificationDocument = {
  configRepo: "test-repo",
  enclaveHost: "test-host",
  releaseDigest: "test-digest",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
  enclaveMeasurement: {
    hpkePublicKey: "mock-hpke-public-key",
    tlsPublicKeyFingerprint: "mock-tls-fingerprint",
    measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
  },
  tlsPublicKey: "test-tls-public-key",
  hpkePublicKey: "mock-hpke-public-key",
  codeFingerprint: "test-code-fingerprint",
  enclaveFingerprint: "test-enclave-fingerprint",
  selectedRouterEndpoint: "test.example.com",
  securityVerified: true,
  steps: {
    fetchDigest: { status: "success" },
    verifyCode: { status: "success" },
    verifyEnclave: { status: "success" },
    compareMeasurements: { status: "success" },
  },
};

const verifyMock = vi.fn(async () => ({
  tlsPublicKeyFingerprint: "mock-tls-fingerprint",
  hpkePublicKey: "mock-hpke-public-key",
  measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
}));

// Track which transport type each mock fetch represents
const mockEhbpFetch = vi.fn();
const mockTlsFetch = vi.fn();

const createSecureFetchMock = vi.fn(
  async (_baseURL: string, _enclaveURL: string | undefined, hpkePublicKey: string | undefined, tlsFingerprint: string | undefined) => {
    if (hpkePublicKey) {
      return mockEhbpFetch;
    }
    if (tlsFingerprint) {
      return mockTlsFetch;
    }
    throw new Error("No transport credentials provided");
  },
);

vi.mock("../src/verifier.js", () => ({
  Verifier: class {
    verify() {
      return verifyMock();
    }
    getVerificationDocument() {
      return mockVerificationDocument;
    }
  },
}));

vi.mock("../src/secure-fetch.js", () => ({
  createSecureFetch: createSecureFetchMock,
}));

describe("SecureClient auto-fallback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEhbpFetch.mockReset();
    mockTlsFetch.mockReset();
  });

  it("should fall back to TLS when EHBP throws NotSupportedError at runtime", async () => {
    // EHBP fetch throws NotSupportedError (simulating missing X25519 support)
    const notSupportedError = new Error("NotSupportedError: DHKEM(X25519, HKDF-SHA256) is unsupported");
    notSupportedError.name = "NotSupportedError";
    mockEhbpFetch.mockRejectedValueOnce(notSupportedError);

    // TLS fetch succeeds
    mockTlsFetch.mockResolvedValueOnce(new Response(JSON.stringify({ success: true })));

    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
      enclaveURL: "https://keys.test.example.com/",
      transport: "auto",
    });

    // After ready(), only EHBP transport should be created (TLS is lazy)
    await client.ready();
    const callsBeforeFetch = createSecureFetchMock.mock.calls.length;
    expect(callsBeforeFetch).toBe(1);

    const response = await client.fetch("/test-endpoint", { method: "GET" });
    const body = await response.json();

    expect(body).toEqual({ success: true });
    expect(mockEhbpFetch).toHaveBeenCalledTimes(1);
    expect(mockTlsFetch).toHaveBeenCalledTimes(1);
    // TLS transport created lazily on fallback
    expect(createSecureFetchMock).toHaveBeenCalledTimes(2);
  });

  it("should use TLS for subsequent requests after fallback", async () => {
    // First EHBP call fails
    const notSupportedError = new Error("NotSupportedError: X25519 unsupported");
    mockEhbpFetch.mockRejectedValueOnce(notSupportedError);

    // TLS calls succeed
    mockTlsFetch.mockResolvedValue(new Response(JSON.stringify({ call: "success" })));

    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
      enclaveURL: "https://keys.test.example.com/",
      transport: "auto",
    });

    // First request triggers fallback
    await client.fetch("/first", { method: "GET" });

    // Second request should use TLS directly (no EHBP attempt)
    mockEhbpFetch.mockClear();
    mockTlsFetch.mockClear();

    await client.fetch("/second", { method: "GET" });

    expect(mockEhbpFetch).not.toHaveBeenCalled();
    expect(mockTlsFetch).toHaveBeenCalledTimes(1);
  });

  it("should not fall back for non-NotSupportedError errors", async () => {
    // EHBP fetch throws a different error
    const networkError = new Error("Network connection failed");
    mockEhbpFetch.mockRejectedValueOnce(networkError);

    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
      enclaveURL: "https://keys.test.example.com/",
      transport: "auto",
    });

    await expect(client.fetch("/test-endpoint", { method: "GET" })).rejects.toThrow("Network connection failed");

    expect(mockEhbpFetch).toHaveBeenCalledTimes(1);
    expect(mockTlsFetch).not.toHaveBeenCalled();
  });

  it("should not attempt fallback when transport is explicitly 'ehbp'", async () => {
    const notSupportedError = new Error("NotSupportedError: X25519 unsupported");
    mockEhbpFetch.mockRejectedValueOnce(notSupportedError);

    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
      enclaveURL: "https://keys.test.example.com/",
      transport: "ehbp",
    });

    await expect(client.fetch("/test-endpoint", { method: "GET" })).rejects.toThrow("NotSupportedError");

    expect(mockEhbpFetch).toHaveBeenCalledTimes(1);
    expect(mockTlsFetch).not.toHaveBeenCalled();
  });

  it("should use EHBP directly when it succeeds in auto mode", async () => {
    mockEhbpFetch.mockResolvedValueOnce(new Response(JSON.stringify({ transport: "ehbp" })));

    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
      enclaveURL: "https://keys.test.example.com/",
      transport: "auto",
    });

    const response = await client.fetch("/test-endpoint", { method: "GET" });
    const body = await response.json();

    expect(body).toEqual({ transport: "ehbp" });
    expect(mockEhbpFetch).toHaveBeenCalledTimes(1);
    expect(mockTlsFetch).not.toHaveBeenCalled();
  });

  it("should handle 'unsupported' in error message for fallback", async () => {
    // Some environments may throw with just 'unsupported' in the message
    const unsupportedError = new Error("The algorithm is unsupported in this environment");
    mockEhbpFetch.mockRejectedValueOnce(unsupportedError);
    mockTlsFetch.mockResolvedValueOnce(new Response(JSON.stringify({ fallback: true })));

    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
      enclaveURL: "https://keys.test.example.com/",
      transport: "auto",
    });

    const response = await client.fetch("/test-endpoint", { method: "GET" });
    const body = await response.json();

    expect(body).toEqual({ fallback: true });
    expect(mockEhbpFetch).toHaveBeenCalledTimes(1);
    expect(mockTlsFetch).toHaveBeenCalledTimes(1);
  });
});
