import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

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
const mockGetSessionRecoveryToken = vi.fn(async () => ({ exportedSecret: new Uint8Array(), requestEnc: new Uint8Array() }));
const createSecureFetchMock = vi.fn(
  async (_baseURL: string, hpkePublicKey: string | undefined) => {
    if (hpkePublicKey) {
      return { fetch: mockFetch, getSessionRecoveryToken: mockGetSessionRecoveryToken };
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

describe("SecureClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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

      client.reset();

      // Derived state should be cleared
      expect(client.getBaseURL()).toBeUndefined();
      expect(client.getEnclaveURL()).toBeUndefined();

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
      const keyMismatchError = new Error("Key config mismatch");
      keyMismatchError.name = "KeyConfigMismatchError";
      mockFetch
        .mockRejectedValueOnce(keyMismatchError)
        .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true })));

      const response = await client.fetch("/test", { method: "GET" });

      // Should have re-attested (initial + recovery)
      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(2);
      expect(await response.json()).toEqual({ ok: true });
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
