import type { SecureTransport } from "../src/encrypted-body-fetch";

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v1";
const PINNED_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2";

const mockVerificationDocument = {
  configRepo: "test-repo",
  enclaveHost: "test-host",
  releaseTag: "test-release",
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
  verifier: { name: "@tinfoilsh/verifier", version: "1.2.0" },
  steps: {
    fetchDigest: { status: "success" },
    verifyCode: { status: "success" },
    verifyEnclave: { status: "success" },
    compareMeasurements: { status: "success" },
  },
};

const verifyMock = vi.fn(async () => ({
  tlsPublicKeyFingerprint: "mock-tls-public-key-fingerprint",
  hpkePublicKey: "mock-hpke-public-key",
  measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
}));
const getVerificationDocumentMock = vi.fn(() => mockVerificationDocument);
const verifierConstructorMock = vi.fn();
const fetchEnclaveAttestationMaterialMock = vi.fn(async () => ({
  enclaveAttestationReport: { format: "test", body: "test" },
  vcek: "test-vcek",
  enclaveCert: "test-cert",
}));

const mockFetch = vi.fn(async () => new Response(JSON.stringify({ message: "success" })));
const mockGetSessionRecoveryToken = vi.fn(async () => ({ exportedSecret: new Uint8Array(), requestEnc: new Uint8Array() }));
const createSecureFetchMock = vi.fn<
  (
    baseURL: string,
    hpkePublicKey?: string,
    tlsPublicKeyFingerprint?: string,
    enclaveURL?: string,
    userCacheSecret?: string,
  ) => Promise<SecureTransport>
>(async () => ({
  fetch: mockFetch as typeof fetch,
  getSessionRecoveryToken: mockGetSessionRecoveryToken,
}));

vi.mock("../src/verifier.js", async () => {
  // Pin validation is real so the SecureClient tests exercise the actual
  // rejection and normalization rules rather than a stand-in.
  const { validatePinnedMeasurement } = await vi.importActual<typeof import("../src/verifier.js")>("../src/verifier.js");
  return {
  cloneVerificationDocument: (document: typeof mockVerificationDocument) => structuredClone(document),
  PINNED_NO_REPO: "pinned_no_repo",
  PINNED_NO_DIGEST: "pinned_no_digest",
  validatePinnedMeasurement,
  fetchEnclaveAttestationMaterial: fetchEnclaveAttestationMaterialMock,
  Verifier: class {
    constructor(options: unknown) {
      verifierConstructorMock(options);
    }
    verify() {
      return verifyMock();
    }
    verifyBundle() {
      return verifyMock();
    }
    getVerificationDocument() {
      return getVerificationDocumentMock();
    }
  },
  FetchError: class FetchError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'FetchError';
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
  assembleAttestationBundle: vi.fn(async () => ({
    domain: "custom-enclave.example.com",
    enclaveAttestationReport: { format: "test", body: "test" },
    digest: "test-digest",
    sigstoreBundle: {},
    vcek: "test-vcek",
  })),
  };
});

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

describe("SecureClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Pin the user cache secret so transport creation resolves it from the
    // environment instead of touching ~/.tinfoil.
    vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "test-secret");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should create a client and initialize securely", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    await client.ready();

    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledWith(
      "https://test.example.com/",
      "mock-hpke-public-key",
      undefined,
      "https://test-router.tinfoil.sh",
      "test-secret",
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

  it("should deduplicate concurrent ready() calls", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    // Call ready() three times concurrently
    const [r1, r2, r3] = await Promise.all([
      client.ready(),
      client.ready(),
      client.ready(),
    ]);

    // Only one attestation should have happened
    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
  });

  it("should return pending verification document before ready()", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    // Before ready(), document should exist but not be verified
    const doc = client.getVerificationDocument();
    expect(doc).toBeTruthy();
    expect(doc.securityVerified).toBe(false);
    expect(doc.steps.fetchDigest.status).toBe("pending");
    expect(doc.steps.verifyCode.status).toBe("pending");
    expect(doc.steps.verifyEnclave.status).toBe("pending");
    expect(doc.steps.compareMeasurements.status).toBe("pending");
  });

  it("should handle verification document retrieval", async () => {
    const { SecureClient } = await import("../src/secure-client");

    const client = new SecureClient({
      baseURL: "https://test.example.com/",
    });

    await client.ready();
    const verificationDocument = client.getVerificationDocument();

    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(verificationDocument).toEqual(mockVerificationDocument);
  });

  it("should return deeply cloned verification document snapshots", async () => {
    const { SecureClient } = await import("../src/secure-client");
    const client = new SecureClient({ baseURL: "https://test.example.com/" });

    await client.ready();
    const expected = structuredClone(mockVerificationDocument);
    const snapshot = client.getVerificationDocument();
    snapshot.securityVerified = false;
    snapshot.releaseTag = "modified";
    snapshot.verifier!.name = "modified";
    snapshot.steps.verifyCode.status = "failed";
    snapshot.codeMeasurement.registers.push("modified");
    snapshot.enclaveMeasurement.measurement.registers.push("modified");

    expect(client.getVerificationDocument()).toEqual(expected);
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

  describe("reset()", () => {
    it("should re-attest when ready() is called after reset()", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });

      await client.ready();
      expect(verifyMock).toHaveBeenCalledTimes(1);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(1);

      client.reset();
      await client.ready();

      // Attestation and transport should have been re-established
      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(2);
    });

    it("should re-attest lazily when fetch is called after reset()", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });

      await client.fetch("/test", { method: "GET" });
      expect(verifyMock).toHaveBeenCalledTimes(1);

      client.reset();

      // No attestation yet — reset is lazy
      expect(verifyMock).toHaveBeenCalledTimes(1);

      await client.fetch("/test", { method: "GET" });

      // Now it should have re-attested
      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(2);
    });

    it("should clear verification document after reset()", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });

      await client.ready();
      const doc = client.getVerificationDocument();
      expect(doc).toEqual(mockVerificationDocument);

      client.reset();
      await client.ready();

      // Should get a fresh verification document
      const newDoc = client.getVerificationDocument();
      expect(newDoc).toEqual(mockVerificationDocument);
      expect(verifyMock).toHaveBeenCalledTimes(2);
    });

    it("should be safe to call reset() multiple times", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });

      await client.ready();

      client.reset();
      client.reset();
      client.reset();

      await client.ready();

      // Should only have attested twice total (initial + one after resets)
      expect(verifyMock).toHaveBeenCalledTimes(2);
    });

    it("should clear resolved URLs after reset()", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient();

      await client.ready();
      expect(client.getBaseURL()).toBe("https://test-router.tinfoil.sh/v1/");
      expect(client.getEnclaveURL()).toBe("https://test-router.tinfoil.sh");
      expect(client.getEnclaveBaseURL()).toBe("https://test-router.tinfoil.sh/v1/");

      client.reset();

      // Derived state should be cleared
      expect(client.getBaseURL()).toBeUndefined();
      expect(client.getEnclaveURL()).toBeUndefined();
      expect(client.getEnclaveBaseURL()).toBeUndefined();

      await client.ready();

      // Re-derived from fresh bundle
      expect(client.getBaseURL()).toBe("https://test-router.tinfoil.sh/v1/");
      expect(client.getEnclaveURL()).toBe("https://test-router.tinfoil.sh");
    });
  });

  describe("init recovery", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should retry once on FetchError then succeed", async () => {
      const { FetchError } = await import("../src/verifier.js");
      verifyMock
        .mockRejectedValueOnce(new FetchError("network timeout"))
        .mockResolvedValueOnce({
          tlsPublicKeyFingerprint: undefined,
          hpkePublicKey: "mock-hpke-public-key",
          measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
        });

      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      const readyPromise = client.ready();
      await vi.advanceTimersByTimeAsync(1000);
      await readyPromise;

      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
    });

    it("should retry once on AttestationError then succeed", async () => {
      const { AttestationError } = await import("../src/verifier.js");
      verifyMock
        .mockRejectedValueOnce(new AttestationError("stale report"))
        .mockResolvedValueOnce({
          tlsPublicKeyFingerprint: undefined,
          hpkePublicKey: "mock-hpke-public-key",
          measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
        });

      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      const readyPromise = client.ready();
      await vi.advanceTimersByTimeAsync(1000);
      await readyPromise;

      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
    });

    it("should propagate after second transient failure", async () => {
      const { FetchError } = await import("../src/verifier.js");
      verifyMock
        .mockRejectedValueOnce(new FetchError("first failure"))
        .mockRejectedValueOnce(new FetchError("second failure"));

      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      // Attach rejection handler before advancing timers to avoid unhandled rejection
      const assertion = expect(client.ready()).rejects.toThrow("second failure");
      await vi.advanceTimersByTimeAsync(1000);
      await assertion;
      expect(verifyMock).toHaveBeenCalledTimes(2);
    });

    it("should not retry on ConfigurationError", async () => {
      const { ConfigurationError } = await import("../src/verifier.js");
      verifyMock.mockRejectedValueOnce(new ConfigurationError("bad config"));

      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      await expect(client.ready()).rejects.toThrow("bad config");
      expect(verifyMock).toHaveBeenCalledTimes(1);
    });

    it("should not retry on unknown errors", async () => {
      verifyMock.mockRejectedValueOnce(new TypeError("unexpected bug"));

      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      await expect(client.ready()).rejects.toThrow("unexpected bug");
      expect(verifyMock).toHaveBeenCalledTimes(1);
    });

    it.each(["compareMeasurements", "verifyCertificate"])("preserves a terminal %s failure document", async failedStep => {
      const { AttestationError } = await import("../src/verifier.js");
      const { SecureClient } = await import("../src/secure-client");
      const error = new AttestationError(`${failedStep} failed`);
      const failedDocument = {
        ...structuredClone(mockVerificationDocument),
        securityVerified: false,
        steps: {
          ...mockVerificationDocument.steps,
          [failedStep]: { status: "failed", error: error.message },
        },
      };
      verifyMock.mockRejectedValueOnce(error).mockRejectedValueOnce(error);
      getVerificationDocumentMock.mockReturnValueOnce(failedDocument).mockReturnValueOnce(failedDocument);
      const client = new SecureClient();

      const rejection = expect(client.ready()).rejects.toBe(error);
      await vi.runAllTimersAsync();
      await rejection;

      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(client.getVerificationDocument()).toEqual(failedDocument);
      expect(client.getBaseURL()).toBeUndefined();
      expect(client.getEnclaveURL()).toBeUndefined();
      expect(Reflect.get(client, "attestedTlsPublicKeyFingerprint")).toBeUndefined();
      await expect(client.getSessionRecoveryToken()).rejects.toThrow("No session recovery token available");
      expect(createSecureFetchMock).not.toHaveBeenCalled();
      expect(mockFetch).not.toHaveBeenCalled();

      client.reset();
      const pending = client.getVerificationDocument();
      expect(pending.securityVerified).toBe(false);
      expect(pending.steps.compareMeasurements.status).toBe("pending");
      expect(pending.steps.otherError).toBeUndefined();
      expect(Object.values(pending.steps).some(step => step?.status === "failed")).toBe(false);
    });

    it.each([false, true])("records terminal transport creation failure (retryable: %s)", async retryable => {
      const { AttestationError } = await import("../src/verifier.js");
      const { SecureClient } = await import("../src/secure-client");
      const error = retryable ? new AttestationError("transport unavailable") : new Error("transport unavailable");
      const successfulDocument = {
        ...structuredClone(mockVerificationDocument),
        verifiedAt: "2026-01-01T00:00:00.000Z",
      };
      createSecureFetchMock.mockRejectedValueOnce(error);
      getVerificationDocumentMock.mockReturnValueOnce(successfulDocument);
      if (retryable) {
        createSecureFetchMock.mockRejectedValueOnce(error);
        getVerificationDocumentMock.mockReturnValueOnce(successfulDocument);
      }
      const client = new SecureClient();

      const rejection = expect(client.ready()).rejects.toBe(error);
      await vi.runAllTimersAsync();
      await rejection;

      expect(createSecureFetchMock).toHaveBeenCalledTimes(retryable ? 2 : 1);
      const failed = client.getVerificationDocument();
      expect(failed.securityVerified).toBe(false);
      expect(failed.verifiedAt).toBeUndefined();
      expect(failed.steps.verifyEnclave.status).toBe("success");
      expect(failed.steps.otherError).toEqual({ status: "failed", error: error.message });
      expect(client.getBaseURL()).toBeUndefined();
      expect(client.getEnclaveURL()).toBeUndefined();
      expect(Reflect.get(client, "attestedTlsPublicKeyFingerprint")).toBeUndefined();
      await expect(client.getSessionRecoveryToken()).rejects.toThrow("No session recovery token available");
      expect(mockFetch).not.toHaveBeenCalled();
      expect(successfulDocument.securityVerified).toBe(true);

      const nextAttempt = client.ready();
      expect(client.getVerificationDocument().steps.otherError).toBeUndefined();
      await nextAttempt;
      expect(client.getVerificationDocument().securityVerified).toBe(true);
    });

    it("retains pin details and records terminal material-fetch failure", async () => {
      const { FetchError } = await import("../src/verifier.js");
      const { SecureClient } = await import("../src/secure-client");
      const pinnedMeasurement = {
        snp_measurement: "a".repeat(96),
      };
      const expectedMeasurement = { type: PINNED_MEASUREMENT_TYPE, registers: [pinnedMeasurement.snp_measurement] };
      const error = new FetchError("material unavailable");
      fetchEnclaveAttestationMaterialMock.mockRejectedValueOnce(error).mockRejectedValueOnce(error);
      const client = new SecureClient({ enclaveURL: "https://custom.example.com", pinnedMeasurement });

      const rejection = expect(client.ready()).rejects.toBe(error);
      await vi.runAllTimersAsync();
      await rejection;

      const failed = client.getVerificationDocument();
      expect(failed.securityVerified).toBe(false);
      expect(failed.configRepo).toBe("pinned_no_repo");
      expect(failed.releaseDigest).toBe("pinned_no_digest");
      expect(failed.codeMeasurement).toEqual(expectedMeasurement);
      expect(failed.steps.fetchDigest.status).toBe("skipped");
      expect(failed.steps.verifyCode.status).toBe("skipped");
      expect(failed.steps.otherError).toEqual({ status: "failed", error: error.message });
      expect(verifyMock).not.toHaveBeenCalled();
      expect(createSecureFetchMock).not.toHaveBeenCalled();

      client.reset();
      expect(client.getVerificationDocument().codeMeasurement).toEqual(expectedMeasurement);
      expect(client.getVerificationDocument().steps.otherError).toBeUndefined();
    });
  });

  describe("constructor validation", () => {
    it("should throw ConfigurationError when configRepo is set without enclaveURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => {
        new SecureClient({ configRepo: "custom/repo" });
      }).toThrow("configRepo requires enclaveURL");
    });

    it("should warn when enclaveURL is set without configRepo", async () => {
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const { SecureClient } = await import("../src/secure-client");

      new SecureClient({ enclaveURL: "https://custom.example.com" });

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("[tinfoil] No configRepo specified"),
      );
      consoleSpy.mockRestore();
    });

    it("should not warn when both enclaveURL and configRepo are set", async () => {
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const { SecureClient } = await import("../src/secure-client");

      new SecureClient({
        enclaveURL: "https://custom.example.com",
        configRepo: "custom/repo",
      });

      expect(consoleSpy).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it("should not warn or throw when neither enclaveURL nor configRepo are set", async () => {
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const { SecureClient } = await import("../src/secure-client");

      expect(() => new SecureClient()).not.toThrow();
      expect(consoleSpy).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it("should allow a non-HTTPS baseURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => {
        new SecureClient({ baseURL: "http://proxy.example.com" });
      }).not.toThrow();
    });

    it.each(["", "not a URL", "ftp://proxy.example.com"])(
      "should throw ConfigurationError for invalid baseURL %j",
      async (baseURL) => {
        const { SecureClient } = await import("../src/secure-client");

        expect(() => {
          new SecureClient({ baseURL });
        }).toThrow("baseURL must be a valid HTTP(S) URL");
      },
    );

    it("should throw ConfigurationError when attestationBundleURL is not HTTPS", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => {
        new SecureClient({ attestationBundleURL: "http://atc.example.com" });
      }).toThrow("attestationBundleURL must use HTTPS");
    });

    it("should allow TLS transport with a baseURL on the enclave origin", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test-router.tinfoil.sh/custom/",
        transport: "tls",
      });
      await expect(client.ready()).resolves.toBeUndefined();
      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://test-router.tinfoil.sh/custom/",
        undefined,
        "mock-tls-public-key-fingerprint",
        "https://test-router.tinfoil.sh",
        "test-secret",
      );
    });

    it("should reject TLS transport with a proxy baseURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://proxy.example.com",
        transport: "tls",
      });
      await expect(client.ready()).rejects.toThrow(
        "TLS transport requires baseURL to use the verified enclave origin",
      );
      expect(createSecureFetchMock).not.toHaveBeenCalled();
    });

    it("should throw ConfigurationError for an empty enclaveURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => {
        new SecureClient({ enclaveURL: "" });
      }).toThrow("enclaveURL must use HTTPS");
    });

    it("should throw ConfigurationError for an unparseable enclaveURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => {
        new SecureClient({ enclaveURL: "https://" });
      }).toThrow("enclaveURL must be a valid HTTPS URL");
    });

    it("should throw ConfigurationError for an empty attestationBundleURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => {
        new SecureClient({ attestationBundleURL: "" });
      }).toThrow("attestationBundleURL must use HTTPS");
    });
  });

  describe("pinnedMeasurement option", () => {
    const PINNED_REGISTER = "a".repeat(96);
    const pinnedMeasurement = { snp_measurement: PINNED_REGISTER };

    it("requires enclaveURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => new SecureClient({ pinnedMeasurement })).toThrow("pinnedMeasurement requires enclaveURL");
    });

    it("cannot be combined with configRepo or attestationBundleURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => new SecureClient({
        enclaveURL: "https://custom.example.com",
        configRepo: "custom/repo",
        pinnedMeasurement,
      })).toThrow("cannot be combined with configRepo");
      expect(() => new SecureClient({
        enclaveURL: "https://custom.example.com",
        attestationBundleURL: "https://atc.example.com",
        pinnedMeasurement,
      })).toThrow("cannot be combined with attestationBundleURL");
    });

    it("does not warn about a missing configRepo", async () => {
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const { SecureClient } = await import("../src/secure-client");

      new SecureClient({ enclaveURL: "https://custom.example.com", pinnedMeasurement });

      expect(consoleSpy).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it("fetches attestation material from the enclave and verifies with the pinned measurement", async () => {
      const { fetchAttestationBundle } = await import("../src/atc.js");
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ enclaveURL: "https://custom.example.com", pinnedMeasurement });
      await client.ready();

      expect(fetchAttestationBundle).not.toHaveBeenCalled();
      expect(fetchEnclaveAttestationMaterialMock).toHaveBeenCalledWith("custom.example.com");
      expect(verifierConstructorMock).toHaveBeenCalledWith({ pinnedMeasurement });
      expect(client.getEnclaveURL()).toBe("https://custom.example.com");
      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://custom.example.com/v1/",
        "mock-hpke-public-key",
        undefined,
        "https://custom.example.com",
        "test-secret",
      );
    });

    it("reports the pin in the pending verification document", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ enclaveURL: "https://custom.example.com", pinnedMeasurement });
      const doc = client.getVerificationDocument();

      expect(doc.configRepo).toBe("pinned_no_repo");
      expect(doc.releaseDigest).toBe("pinned_no_digest");
      expect(doc.codeMeasurement).toEqual({ type: PINNED_MEASUREMENT_TYPE, registers: [PINNED_REGISTER] });
      expect(doc.steps.fetchDigest.status).toBe("skipped");
      expect(doc.steps.verifyCode.status).toBe("skipped");
      expect(doc.steps.verifyEnclave.status).toBe("pending");
    });

    it("rejects a supplied null pin instead of falling back to release verification", async () => {
      const { fetchAttestationBundle } = await import("../src/atc.js");
      const { SecureClient } = await import("../src/secure-client");

      expect(() => new SecureClient({
        enclaveURL: "https://custom.example.com",
        pinnedMeasurement: null as unknown as typeof pinnedMeasurement,
      })).toThrow("pinnedMeasurement must be an object");
      expect(fetchAttestationBundle).not.toHaveBeenCalled();
    });

    it.each([
      ["empty object", {}],
      ["unsupported TDX", { tdx_measurement: { rtmr1: PINNED_REGISTER, rtmr2: PINNED_REGISTER } }],
      ["non-string register", { snp_measurement: [PINNED_REGISTER] }],
      ["short register", { snp_measurement: "abc" }],
    ])("rejects a malformed pin before any network access: %s", async (_name, malformed) => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => new SecureClient({
        enclaveURL: "https://custom.example.com",
        pinnedMeasurement: malformed as typeof pinnedMeasurement,
      })).toThrow("pinnedMeasurement");
      expect(fetchEnclaveAttestationMaterialMock).not.toHaveBeenCalled();
    });

    it("snapshots the pin so later mutation of the caller's object has no effect", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const callerPin = { snp_measurement: PINNED_REGISTER.toUpperCase() };
      const client = new SecureClient({ enclaveURL: "https://custom.example.com", pinnedMeasurement: callerPin });
      callerPin.snp_measurement = "f".repeat(96);

      await client.ready();

      // The verifier receives the normalized snapshot taken at construction.
      expect(verifierConstructorMock).toHaveBeenCalledWith({ pinnedMeasurement });

      // A reset and re-verification (key rotation path) still uses the snapshot.
      verifierConstructorMock.mockClear();
      client.reset();
      await client.ready();
      expect(verifierConstructorMock).toHaveBeenCalledWith({ pinnedMeasurement });
    });

    it("fetches attestation material from the configured enclave origin, including its port", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ enclaveURL: "https://custom.example.com:8443", pinnedMeasurement });
      await client.ready();

      expect(fetchEnclaveAttestationMaterialMock).toHaveBeenCalledWith("custom.example.com:8443");
      expect(client.getEnclaveURL()).toBe("https://custom.example.com:8443");
      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://custom.example.com:8443/v1/",
        "mock-hpke-public-key",
        undefined,
        "https://custom.example.com:8443",
        "test-secret",
      );
    });
  });

  describe("userCacheSecret option", () => {
    it("beats the environment variable", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ userCacheSecret: "option-secret" });
      await client.ready();

      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://test-router.tinfoil.sh/v1/",
        "mock-hpke-public-key",
        undefined,
        "https://test-router.tinfoil.sh",
        "option-secret",
      );
    });

    it("treats explicit empty as unset", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ userCacheSecret: "" });
      await client.ready();

      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://test-router.tinfoil.sh/v1/",
        "mock-hpke-public-key",
        undefined,
        "https://test-router.tinfoil.sh",
        "test-secret",
      );
    });
  });

  describe("attestation bundle paths", () => {
    it("should use fetchAttestationBundle via GET when no custom options", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { fetchAttestationBundle } = await import("../src/atc.js");

      const client = new SecureClient();
      await client.ready();

      expect(fetchAttestationBundle).toHaveBeenCalledTimes(1);
      expect(fetchAttestationBundle).toHaveBeenCalledWith({
        atcBaseUrl: undefined,
        enclaveURL: undefined,
        configRepo: undefined,
      });
    });

    it("should pass enclaveURL and configRepo to fetchAttestationBundle", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { fetchAttestationBundle } = await import("../src/atc.js");

      const client = new SecureClient({
        enclaveURL: "https://my-enclave.example.com",
        configRepo: "custom/repo",
      });
      await client.ready();

      expect(fetchAttestationBundle).toHaveBeenCalledTimes(1);
      expect(fetchAttestationBundle).toHaveBeenCalledWith({
        atcBaseUrl: undefined,
        enclaveURL: "https://my-enclave.example.com",
        configRepo: "custom/repo",
      });
    });
  });

  describe("KeyConfigMismatchError recovery", () => {
    it("should re-attest and retry on KeyConfigMismatchError", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });
      await client.ready();
      expect(verifyMock).toHaveBeenCalledTimes(1);

      // First call throws KeyConfigMismatchError, second succeeds
      const { KeyConfigMismatchError } = await import("ehbp");
      const keyMismatchError = new KeyConfigMismatchError("Key config mismatch");
      mockFetch
        .mockRejectedValueOnce(keyMismatchError)
        .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true })));

      const response = await client.fetch("/test", { method: "GET" });

      // Should have re-attested (initial + recovery)
      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(2);
      expect(await response.json()).toEqual({ ok: true });
    });

    it("should replace verification metadata after automatic re-attestation", async () => {
      const firstDocument = {
        ...mockVerificationDocument,
        releaseTag: "v1.0.0",
        verifiedAt: "2026-01-01T00:00:00.000Z",
      };
      const replacementDocument = {
        ...mockVerificationDocument,
        releaseTag: "v1.1.0",
        verifiedAt: "2026-02-01T00:00:00.000Z",
      };
      getVerificationDocumentMock
        .mockReturnValueOnce(firstDocument)
        .mockReturnValueOnce(replacementDocument);
      const { KeyConfigMismatchError } = await import("ehbp");
      mockFetch
        .mockRejectedValueOnce(new KeyConfigMismatchError("Key config mismatch"))
        .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true })));
      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      await client.ready();
      expect(client.getVerificationDocument()).toMatchObject({
        releaseTag: firstDocument.releaseTag,
        verifiedAt: firstDocument.verifiedAt,
      });

      await client.fetch("/test", { method: "GET" });

      expect(client.getVerificationDocument()).toMatchObject({
        releaseTag: replacementDocument.releaseTag,
        verifiedAt: replacementDocument.verifiedAt,
      });
    });

    it("should retry eligible requests with the injected cache secret", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { withUserCacheSecret } = await import("../src/user-cache-secret");
      const { KeyConfigMismatchError } = await import("ehbp");

      const firstAttempt = vi.fn(async () => {
        throw new KeyConfigMismatchError("Key config mismatch");
      }) as typeof fetch;
      const recoveredAttempt = vi.fn(async () =>
        new Response(JSON.stringify({ ok: true }))
      ) as typeof fetch;
      createSecureFetchMock
        .mockImplementationOnce(async (baseURL, _hpke, _tls, _enclave, secret) => {
          return {
            fetch: withUserCacheSecret(firstAttempt, baseURL!, secret!),
            getSessionRecoveryToken: mockGetSessionRecoveryToken,
          };
        })
        .mockImplementationOnce(async (baseURL, _hpke, _tls, _enclave, secret) => {
          return {
            fetch: withUserCacheSecret(recoveredAttempt, baseURL!, secret!),
            getSessionRecoveryToken: mockGetSessionRecoveryToken,
          };
        });

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });
      const response = await client.fetch("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: "m" }),
      });

      expect(await response.json()).toEqual({ ok: true });
      expect(firstAttempt).toHaveBeenCalledTimes(1);
      expect(recoveredAttempt).toHaveBeenCalledTimes(1);
      for (const [, init] of [
        ...vi.mocked(firstAttempt).mock.calls,
        ...vi.mocked(recoveredAttempt).mock.calls,
      ]) {
        expect(JSON.parse(init!.body as string).user_cache_secret).toBe("test-secret");
      }
    });

    it("should propagate non-KeyConfigMismatchError errors", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://test.example.com/",
      });
      await client.ready();

      mockFetch.mockRejectedValueOnce(new Error("network failure"));

      await expect(
        client.fetch("/test", { method: "GET" }),
      ).rejects.toThrow("network failure");

      // Should NOT have re-attested
      expect(verifyMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("URL resolution", () => {
    it("Case 1: no config — derives both URLs from bundle", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient();
      await client.ready();

      expect(client.getEnclaveURL()).toBe("https://test-router.tinfoil.sh");
      expect(client.getBaseURL()).toBe("https://test-router.tinfoil.sh/v1/");

      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://test-router.tinfoil.sh/v1/",
        "mock-hpke-public-key",
        undefined,
        "https://test-router.tinfoil.sh",
        "test-secret",
      );
    });

    it("Case 2: proxy — baseURL is proxy, enclaveURL from bundle", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://my-proxy.com/api/",
      });
      await client.ready();

      expect(client.getEnclaveURL()).toBe("https://test-router.tinfoil.sh");
      expect(client.getBaseURL()).toBe("https://my-proxy.com/api/");

      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://my-proxy.com/api/",
        "mock-hpke-public-key",
        undefined,
        "https://test-router.tinfoil.sh",
        "test-secret",
      );
    });

    it("Case 3: custom enclave — enclaveURL from config, baseURL derived", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        enclaveURL: "https://my-enclave.example.com",
      });
      await client.ready();

      expect(client.getEnclaveURL()).toBe("https://my-enclave.example.com");
      expect(client.getBaseURL()).toBe("https://my-enclave.example.com/v1/");

      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://my-enclave.example.com/v1/",
        "mock-hpke-public-key",
        undefined,
        "https://my-enclave.example.com",
        "test-secret",
      );
    });

    it("Case 4: proxy + custom enclave — both from config", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://my-proxy.com/api/",
        enclaveURL: "https://my-enclave.example.com",
      });
      await client.ready();

      expect(client.getEnclaveURL()).toBe("https://my-enclave.example.com");
      expect(client.getBaseURL()).toBe("https://my-proxy.com/api/");

      expect(createSecureFetchMock).toHaveBeenCalledWith(
        "https://my-proxy.com/api/",
        "mock-hpke-public-key",
        undefined,
        "https://my-enclave.example.com",
        "test-secret",
      );
    });

    it("Case 4: reset preserves proxy + custom enclave config", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        baseURL: "https://my-proxy.com/api/",
        enclaveURL: "https://my-enclave.example.com",
      });
      await client.ready();

      client.reset();
      await client.ready();

      expect(client.getEnclaveURL()).toBe("https://my-enclave.example.com");
      expect(client.getBaseURL()).toBe("https://my-proxy.com/api/");
      expect(verifyMock).toHaveBeenCalledTimes(2);
    });
  });
});
