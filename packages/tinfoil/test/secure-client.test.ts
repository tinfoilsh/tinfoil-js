import type { SecureTransport } from "../src/encrypted-body-fetch";

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VerificationError, PredicateType, measurementFingerprint, VERIFIER_NAME, VERIFIER_VERSION } from "@tinfoilsh/verifier";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const MOCK_REGISTER = "ab".repeat(48);

// VerifiedDocumentV3 fixture returned by the mocked verifyDocumentV3.
const mockVerified = {
  codeDigest: "test-digest",
  codeTag: "test-release",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  enclaveMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  cryptoMaterial: [
    { id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: "mock-tls-public-key-fingerprint" },
    { id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: "mock-hpke-public-key" },
  ],
};

// The document SecureClient assembles from mockVerified (verifiedAt is dynamic).
const expectedVerificationDocument = {
  schemaVersion: 1,
  configRepo: "tinfoilsh/confidential-model-router",
  enclaveHost: "test-router.tinfoil.sh",
  releaseTag: "test-release",
  releaseDigest: "test-digest",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  enclaveMeasurement: {
    tlsPublicKeyFingerprint: "mock-tls-public-key-fingerprint",
    hpkePublicKey: "mock-hpke-public-key",
    measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [MOCK_REGISTER] },
  },
  tlsPublicKey: "mock-tls-public-key-fingerprint",
  hpkePublicKey: "mock-hpke-public-key",
  codeFingerprint: MOCK_REGISTER,
  enclaveFingerprint: MOCK_REGISTER,
  selectedRouterEndpoint: "test-router.tinfoil.sh",
  securityVerified: true,
  verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION },
  steps: {
    fetchDigest: { status: "success" },
    verifyCode: { status: "success" },
    verifyEnclave: { status: "success" },
    compareMeasurements: { status: "success" },
  },
};

const fetchAttestationMock = vi.fn(async (_host: string, _nonce: Uint8Array) => new Uint8Array([1, 2, 3]));
const verifyMock = vi.fn(async (_doc: Uint8Array, _nonce: Uint8Array, _repo: string) => mockVerified);
const tlsPublicKeyFPMock = vi.fn((_v: typeof mockVerified) => "mock-tls-public-key-fingerprint");
const hpkePublicKeyMock = vi.fn((_v: typeof mockVerified) => "mock-hpke-public-key");

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

vi.mock("../src/verifier.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/verifier.js")>();
  return {
    ...original,
    fetchAttestation: (host: string, nonce: Uint8Array) => fetchAttestationMock(host, nonce),
    verifyDocumentV3: (doc: Uint8Array, nonce: Uint8Array, repo: string) => verifyMock(doc, nonce, repo),
    tlsPublicKeyFP: (v: typeof mockVerified) => tlsPublicKeyFPMock(v),
    hpkePublicKey: (v: typeof mockVerified) => hpkePublicKeyMock(v),
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
    await Promise.all([
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
    expect(verificationDocument).toMatchObject(expectedVerificationDocument);
    expect(typeof verificationDocument.verifiedAt).toBe("string");
  });

  it("should return deeply cloned verification document snapshots", async () => {
    const { SecureClient } = await import("../src/secure-client");
    const client = new SecureClient({ baseURL: "https://test.example.com/" });

    await client.ready();
    const expected = client.getVerificationDocument();
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

  describe("v3 verification flow", () => {
    it("fetches the attestation document with a fresh 32-byte nonce and verifies it against the config repo", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient();
      await client.ready();

      expect(fetchAttestationMock).toHaveBeenCalledTimes(1);
      const [host, nonce] = fetchAttestationMock.mock.calls[0];
      expect(host).toBe("test-router.tinfoil.sh");
      expect(nonce).toBeInstanceOf(Uint8Array);
      expect(nonce.length).toBe(32);

      expect(verifyMock).toHaveBeenCalledTimes(1);
      const [docBytes, verifyNonce, repo] = verifyMock.mock.calls[0];
      expect(docBytes).toEqual(new Uint8Array([1, 2, 3]));
      expect(verifyNonce).toBe(nonce);
      expect(repo).toBe("tinfoilsh/confidential-model-router");
    });

    it("computes TDX fingerprints from the verified quote registers (Go hardware-measurement rule)", async () => {
      const TDX_GUEST_V2 = "https://tinfoil.sh/predicate/tdx-guest/v2";
      const RTMR3_ZERO = "0".repeat(96);
      const mrtd = "11".repeat(48);
      const rtmr0 = "22".repeat(48);
      const rtmr1 = "33".repeat(48);
      const rtmr2 = "44".repeat(48);
      verifyMock.mockResolvedValueOnce({
        ...mockVerified,
        codeMeasurement: { type: PredicateType.SnpTdxMultiplatformV1, registers: ["55".repeat(48), rtmr1, rtmr2] },
        enclaveMeasurement: { type: TDX_GUEST_V2, registers: [mrtd, rtmr0, rtmr1, rtmr2, RTMR3_ZERO] },
      });

      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient();
      await client.ready();

      const doc = client.getVerificationDocument();
      expect(doc.hardwareMeasurement).toEqual({ MRTD: mrtd, RTMR0: rtmr0 });
      expect(doc.codeFingerprint).toBe(
        await measurementFingerprint({
          type: PredicateType.SnpTdxMultiplatformV1,
          registers: [mrtd, rtmr0, rtmr1, rtmr2, RTMR3_ZERO],
        }),
      );
      expect(doc.enclaveFingerprint).toBe(
        await measurementFingerprint({
          type: TDX_GUEST_V2,
          registers: [mrtd, rtmr0, rtmr1, rtmr2, RTMR3_ZERO],
        }),
      );
    });

    it("rejects with an AttestationError carrying the layered rejection as cause", async () => {
      vi.useFakeTimers();
      try {
        // Rejected on both the initial attempt and the automatic retry. The
        // final reset() restores the pending document (existing behaviour),
        // so the rejection itself carries the attribution.
        verifyMock
          .mockRejectedValueOnce(new VerificationError("POLICY_REJECTED", "measurement mismatch"))
          .mockRejectedValueOnce(new VerificationError("POLICY_REJECTED", "measurement mismatch"));

        const { SecureClient } = await import("../src/secure-client");
        const { AttestationError } = await import("../src/verifier.js");
        const client = new SecureClient();

        const assertion = expect(client.ready()).rejects.toSatisfy((error: Error) => {
          expect(error).toBeInstanceOf(AttestationError);
          expect(error.message).toMatch(/measurement mismatch/);
          expect((error.cause as VerificationError).layer).toBe("POLICY_REJECTED");
          return true;
        });
        await vi.advanceTimersByTimeAsync(1000);
        await assertion;

        const doc = client.getVerificationDocument();
        expect(doc.securityVerified).toBe(false);
        expect(doc.steps.fetchDigest.status).toBe("pending");
        expect(createSecureFetchMock).not.toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });

    it("fails binding when the document endorses no HPKE key", async () => {
      vi.useFakeTimers();
      try {
        const bindingFailure = () => {
          throw new Error('document endorses no "hpke" crypto material');
        };
        hpkePublicKeyMock
          .mockImplementationOnce(bindingFailure)
          .mockImplementationOnce(bindingFailure);

        const { SecureClient } = await import("../src/secure-client");
        const client = new SecureClient();

        const assertion = expect(client.ready()).rejects.toThrow(/binding: document endorses no "hpke"/);
        await vi.advanceTimersByTimeAsync(1000);
        await assertion;

        expect(createSecureFetchMock).not.toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });

    it("wraps attestation fetch failures in FetchError", async () => {
      vi.useFakeTimers();
      try {
        fetchAttestationMock
          .mockRejectedValueOnce(new Error("HTTP 502"))
          .mockRejectedValueOnce(new Error("HTTP 502"));

        const { SecureClient } = await import("../src/secure-client");
        const { FetchError } = await import("../src/verifier.js");
        const client = new SecureClient();

        const assertion = expect(client.ready()).rejects.toSatisfy((error: Error) => {
          expect(error).toBeInstanceOf(FetchError);
          expect(error.message).toMatch(/Failed to fetch attestation document from test-router.tinfoil.sh: HTTP 502/);
          return true;
        });
        await vi.advanceTimersByTimeAsync(1000);
        await assertion;

        expect(verifyMock).not.toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });

    it("repopulates the document with fresh v3 facts after a rejected first attempt", async () => {
      verifyMock.mockRejectedValueOnce(new VerificationError("POLICY_REJECTED", "measurement mismatch"));

      vi.useFakeTimers();
      try {
        const { SecureClient } = await import("../src/secure-client");
        const client = new SecureClient();

        const readyPromise = client.ready();
        await vi.advanceTimersByTimeAsync(1000);
        await readyPromise;

        const doc = client.getVerificationDocument();
        expect(doc.securityVerified).toBe(true);
        expect(doc.steps.compareMeasurements.status).toBe("success");
        expect(verifyMock).toHaveBeenCalledTimes(2);
      } finally {
        vi.useRealTimers();
      }
    });
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
      expect(doc).toMatchObject(expectedVerificationDocument);

      client.reset();
      await client.ready();

      // Should get a fresh verification document
      const newDoc = client.getVerificationDocument();
      expect(newDoc).toMatchObject(expectedVerificationDocument);
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

      // Re-derived from fresh discovery
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
      verifyMock.mockRejectedValueOnce(new FetchError("network timeout"));

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
      verifyMock.mockRejectedValueOnce(new AttestationError("stale report"));

      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      const readyPromise = client.ready();
      await vi.advanceTimersByTimeAsync(1000);
      await readyPromise;

      expect(verifyMock).toHaveBeenCalledTimes(2);
      expect(createSecureFetchMock).toHaveBeenCalledTimes(1);
    });

    it("should retry once on a VerificationError rejection then succeed", async () => {
      verifyMock.mockRejectedValueOnce(new VerificationError("QUOTE_REJECTED", "stale quote"));

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

    it("should throw ConfigurationError for an empty attestationBundleURL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      expect(() => {
        new SecureClient({ attestationBundleURL: "" });
      }).toThrow("attestationBundleURL must use HTTPS");
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

  describe("enclave discovery", () => {
    it("should discover a router when no enclaveURL is configured", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { fetchRouter } = await import("../src/atc.js");

      const client = new SecureClient();
      await client.ready();

      expect(fetchRouter).toHaveBeenCalledTimes(1);
      expect(fetchRouter).toHaveBeenCalledWith(undefined);
      expect(fetchAttestationMock).toHaveBeenCalledWith("test-router.tinfoil.sh", expect.any(Uint8Array));
    });

    it("should pass attestationBundleURL to router discovery", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { fetchRouter } = await import("../src/atc.js");

      const client = new SecureClient({ attestationBundleURL: "https://atc.example.com" });
      await client.ready();

      expect(fetchRouter).toHaveBeenCalledWith("https://atc.example.com");
    });

    it("should skip discovery and attest the configured enclave directly", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { fetchRouter } = await import("../src/atc.js");

      const client = new SecureClient({
        enclaveURL: "https://my-enclave.example.com",
        configRepo: "custom/repo",
      });
      await client.ready();

      expect(fetchRouter).not.toHaveBeenCalled();
      expect(fetchAttestationMock).toHaveBeenCalledWith("my-enclave.example.com", expect.any(Uint8Array));
      expect(verifyMock).toHaveBeenCalledWith(expect.any(Uint8Array), expect.any(Uint8Array), "custom/repo");
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
      verifyMock
        .mockResolvedValueOnce({ ...mockVerified, codeTag: "v1.0.0" })
        .mockResolvedValueOnce({ ...mockVerified, codeTag: "v1.1.0" });
      const { KeyConfigMismatchError } = await import("ehbp");
      mockFetch
        .mockRejectedValueOnce(new KeyConfigMismatchError("Key config mismatch"))
        .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true })));
      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient({ baseURL: "https://test.example.com/" });

      await client.ready();
      expect(client.getVerificationDocument()).toMatchObject({
        releaseTag: "v1.0.0",
      });

      await client.fetch("/test", { method: "GET" });

      expect(client.getVerificationDocument()).toMatchObject({
        releaseTag: "v1.1.0",
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
    it("Case 1: no config — derives both URLs from router discovery", async () => {
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

    it("Case 2: proxy — baseURL is proxy, enclaveURL from discovery", async () => {
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
