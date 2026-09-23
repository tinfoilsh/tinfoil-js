import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const MOCK_REGISTER = "ab".repeat(48);

const verifyMock = vi.fn(async () => ({
  codeDigest: "test-digest",
  codeTag: "test-release",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  enclaveMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  cryptoMaterial: [
    { id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: "fingerprint" },
    { id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: "mock-hpke-public-key" },
  ],
}));

const mockFetch = vi.fn(async () => new Response(null));
const createSecureFetchMock = vi.fn(async () => ({ fetch: mockFetch, getSessionRecoveryToken: vi.fn() }));
const createPinnedRealtimeWSMock = vi.fn(async () => ({}));

vi.mock("../src/verifier.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/verifier.js")>();
  return {
    ...original,
    fetchAttestation: vi.fn(async () => new Uint8Array([1, 2, 3])),
    verifyDocumentV3: () => verifyMock(),
  };
});

vi.mock("../src/secure-fetch.js", () => ({
  createSecureFetch: createSecureFetchMock,
}));

vi.mock("../src/realtime.js", () => ({
  createPinnedRealtimeWS: createPinnedRealtimeWSMock,
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
    // Pin the user cache secret so transport creation resolves it from the
    // environment instead of touching ~/.tinfoil.
    vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "test-secret");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("configures the OpenAI SDK to use the encrypted body transport", async () => {
    const { TinfoilAI } = await import("../src/tinfoil-ai");
    const testBaseURL = "https://test-router.tinfoil.sh/v1/";

    const client = new TinfoilAI({
      apiKey: "test",
      baseURL: testBaseURL,
    });
    await client.ready();

    expect(verifyMock).toHaveBeenCalledTimes(1);
    // Default transport is EHBP; TLS is only used when explicitly configured
    expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledWith(
      testBaseURL,
      "mock-hpke-public-key",
      undefined,
      "https://test-router.tinfoil.sh",
      "test-secret"
    );
  });

  it("provides the encrypted body transport to the AI SDK provider", async () => {
    const { createTinfoilAI } = await import("../src/ai-sdk-provider");
    const provider = await createTinfoilAI("api-key");

    expect(provider).toBeTruthy();
  });

  it("connects realtime sessions directly to the enclave when using a proxy", async () => {
    const { TinfoilAI } = await import("../src/tinfoil-ai");
    const client = new TinfoilAI({
      apiKey: "test",
      baseURL: "http://localhost:3000/v1/",
    });

    await client.realtime({ model: "test-model" });

    expect(createPinnedRealtimeWSMock).toHaveBeenCalledWith(
      { model: "test-model" },
      {
        apiKey: "test",
        baseURL: "https://test-router.tinfoil.sh/v1/",
      },
      expect.any(Object),
    );
  });

  it("TinfoilAI throws when no API key is available (no env var)", async () => {
    const saved = process.env.TINFOIL_API_KEY;
    delete process.env.TINFOIL_API_KEY;
    try {
      const { TinfoilAI } = await import("../src/tinfoil-ai");
      const client = new TinfoilAI(); // no apiKey, no bearerToken, no env var

      // The error surfaces on ready() when OpenAI client is created
      await expect(client.ready()).rejects.toThrow();
    } finally {
      if (saved !== undefined) process.env.TINFOIL_API_KEY = saved;
    }
  });
});
