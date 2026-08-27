import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const MOCK_REGISTER = "ab".repeat(48);

// An enclave that endorses a TLS key but no HPKE key.
const verifyMock = vi.fn(async () => ({
  codeDigest: "test-digest",
  codeTag: "test-release",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  enclaveMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  cryptoMaterial: [
    { id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: "mock-tls-fingerprint" },
  ],
}));

vi.mock("../src/verifier.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/verifier.js")>();
  return {
    ...original,
    fetchAttestation: vi.fn(async () => new Uint8Array([1, 2, 3])),
    verifyDocumentV3: () => verifyMock(),
    // The real tlsPublicKeyFP/hpkePublicKey run against the fixture above:
    // hpkePublicKey throws because the document endorses no hpke entry.
  };
});

// Mock createSecureFetch to simulate browser behavior (throw when no HPKE key)
vi.mock("../src/secure-fetch.js", () => ({
  createSecureFetch: async (_baseURL: string, hpkePublicKey: string | undefined) => {
    if (!hpkePublicKey) {
      throw new Error(
        "HPKE public key not available and TLS-only verification is not supported in browsers. " +
          "Only HPKE-enabled enclaves can be used in browser environments."
      );
    }
    return { fetch: vi.fn(), getSessionRecoveryToken: vi.fn() };
  },
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

describe("SecureClient (browser)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Pin the user cache secret so client init never touches a filesystem.
    vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "test-secret");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should reject initialization when the document endorses no HPKE key", async () => {
    vi.useFakeTimers();
    try {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });

      // Binding failures re-attest once (AttestationError is transient) and
      // then propagate; the transport is never created.
      const assertion = expect(client.ready()).rejects.toThrow(
        /binding: document endorses no "hpke" crypto material/
      );
      await vi.advanceTimersByTimeAsync(1000);
      await assertion;

      expect(verifyMock).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
