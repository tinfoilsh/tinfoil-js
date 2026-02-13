import { describe, it, expect, vi, beforeEach } from "vitest";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v1";

const verifyMock = vi.fn(async () => ({
  tlsPublicKeyFingerprint: "mock-tls-fingerprint",
  hpkePublicKey: undefined, // No HPKE key available
  measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
}));

const mockVerificationDocument = {
  configRepo: "test-repo",
  enclaveHost: "test-host",
  releaseDigest: "test-digest",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
  enclaveMeasurement: {
    hpkePublicKey: undefined,
    tlsPublicKeyFingerprint: "mock-tls-fingerprint",
    measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
  },
  securityVerified: true,
  steps: {
    fetchDigest: { status: "success" as const },
    verifyCode: { status: "success" as const },
    verifyEnclave: { status: "success" as const },
    compareMeasurements: { status: "success" as const },
  },
};

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
  AttestationError: class AttestationError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'AttestationError';
    }
  },
  ConfigurationError: class ConfigurationError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'ConfigurationError';
    }
  },
  FetchError: class FetchError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'FetchError';
    }
  },
  assembleAttestationBundle: vi.fn(async () => ({
    domain: "custom-enclave.example.com",
    enclaveAttestationReport: { format: "test", body: "test" },
    digest: "test-digest",
    sigstoreBundle: {},
    vcek: "test-vcek",
  })),
}));

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
  });

  it("should reject initialization when HPKE is not available in browser", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    await expect(client.ready()).rejects.toThrow(
      /HPKE public key not available and TLS-only verification is not supported in browsers/
    );

    expect(verifyMock).toHaveBeenCalledTimes(1);
  });
});
