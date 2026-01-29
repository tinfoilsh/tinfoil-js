import { describe, it, expect, vi, beforeEach } from "vitest";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v1";

const mockVerificationDocument = {
  configRepo: "test-repo",
  enclaveHost: "test-host",
  releaseDigest: "test-digest",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
  enclaveMeasurement: {
    tlsPublicKeyFingerprint: "fingerprint",
    hpkePublicKey: "mock-hpke-public-key",
    measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
  },
  tlsPublicKey: "test-tls-public-key",
  hpkePublicKey: "mock-hpke-public-key",
  codeFingerprint: "test-code-fingerprint",
  enclaveFingerprint: "test-enclave-fingerprint",
  selectedRouterEndpoint: "test-router.tinfoil.sh",
  securityVerified: true,
  steps: {
    fetchDigest: { status: "success" },
    verifyCode: { status: "success" },
    verifyEnclave: { status: "success" },
    compareMeasurements: { status: "success" },
  },
};

const verifyMock = vi.fn(async () => ({
  tlsPublicKeyFingerprint: "fingerprint",
  hpkePublicKey: "mock-hpke-public-key",
  measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
}));

const mockFetch = vi.fn(async () => new Response(null));
const createSecureFetchMock = vi.fn(async () => mockFetch);

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
  fetchAttestationBundle: vi.fn(async () => ({
    domain: "test-router.tinfoil.sh",
    enclaveAttestationReport: { format: "test", body: "test" },
    digest: "test-digest",
    sigstoreBundle: {},
    vcek: "test-vcek",
  })),
  fetchRouter: vi.fn(async () => "test-router.tinfoil.sh"),
}));

describe("Secure transport integration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("configures the OpenAI SDK to use the encrypted body transport", async () => {
    const { TinfoilAI } = await import("../src/tinfoil-ai");
    const testBaseURL = "https://test-router.tinfoil.sh/v1/";
    const testEnclaveURL = "https://test-router.tinfoil.sh";

    const client = new TinfoilAI({
      apiKey: "test",
      baseURL: testBaseURL,
      enclaveURL: testEnclaveURL,
    });
    await client.ready();

    expect(verifyMock).toHaveBeenCalledTimes(1);
    // In 'auto' mode, only EHBP transport is created initially (TLS created lazily on fallback)
    expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledWith(
      testBaseURL,
      "mock-hpke-public-key",
      undefined
    );
  });

  it("provides the encrypted body transport to the AI SDK provider", async () => {
    const { createTinfoilAI } = await import("../src/ai-sdk-provider");
    const provider = await createTinfoilAI("api-key");

    expect(provider).toBeTruthy();
  });
});
