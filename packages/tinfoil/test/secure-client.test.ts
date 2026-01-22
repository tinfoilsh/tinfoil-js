import { describe, it, expect, vi, beforeEach } from "vitest";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v1";

const mockVerificationDocument = {
  configRepo: "test-repo",
  enclaveHost: "test-host",
  releaseDigest: "test-digest",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
  enclaveMeasurement: {
    hpkePublicKey: "mock-hpke-public-key",
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
  tlsPublicKeyFingerprint: undefined,
  hpkePublicKey: "mock-hpke-public-key",
  measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
}));

const mockFetch = vi.fn(async () => new Response(JSON.stringify({ message: "success" })));
const createSecureFetchMock = vi.fn(
  async (_baseURL: string, _enclaveURL: string | undefined, hpkePublicKey: string | undefined) => {
    if (hpkePublicKey) {
      return mockFetch;
    }
    throw new Error("TLS-only verification not supported in tests");
  },
);

vi.mock("../src/verifier.js", () => ({
  Verifier: class {
    verify() {
      return verifyMock();
    }
    verifyBundle() {
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

vi.mock("../src/atc.js", () => ({
  fetchBundle: vi.fn(async () => ({
    domain: "test-router.tinfoil.sh",
    enclaveAttestationReport: { format: "test", body: "test" },
    digest: "test-digest",
    sigstoreBundle: {},
    vcek: "test-vcek",
  })),
  fetchRouter: vi.fn(async () => "test-router.tinfoil.sh"),
}));

describe("SecureClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should create a client and initialize securely", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
      enclaveURL: "https://keys.test.example.com/",
      configRepo: "test-org/test-repo",
    });

    await client.ready();

    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledWith(
      "https://test.example.com/",
      "https://keys.test.example.com/",
      "mock-hpke-public-key",
      undefined,
    );
  });

  it("should provide a fetch function that works correctly", async () => {
    const mockResponseBody = { test: "response" };
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(mockResponseBody)));

    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    const response = await client.fetch("/test-endpoint", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test: "data" }),
    });

    const responseBody = await response.json();

    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(responseBody).toEqual(mockResponseBody);
  });

  it("should handle verification document retrieval", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    const verificationDocument = await client.getVerificationDocument();

    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(verificationDocument).toEqual(mockVerificationDocument);
  });

  it("should lazily initialize when fetch is first accessed", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    // Verify that initialization hasn't happened yet
    expect(verifyMock).not.toHaveBeenCalled();
    expect(createSecureFetchMock).not.toHaveBeenCalled();

    // Access fetch for the first time - this should trigger initialization
    await client.fetch("/test", { method: "GET" });

    // Verify that initialization happened
    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
  });
});
