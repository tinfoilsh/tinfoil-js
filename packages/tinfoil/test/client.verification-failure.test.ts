import { describe, it, expect, vi, beforeEach } from "vitest";

const createSecureFetchMock = vi.fn(async () => {
  return (async () => new Response(null)) as typeof fetch;
});

vi.mock("../src/verifier.js", () => ({
  Verifier: class {
    verify() {
      throw new Error("verify failed");
    }
    verifyBundle() {
      throw new Error("verify failed");
    }
    getVerificationDocument() {
      return undefined;
    }
  },
  ConfigurationError: class ConfigurationError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'ConfigurationError';
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

describe("Client verification gating", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("blocks client creation and requests when verification fails", async () => {
    const { TinfoilAI } = await import("../src/tinfoil-ai");
    const client = new TinfoilAI({ apiKey: "test" });

    await expect(client.ready()).rejects.toThrow(/verify/);

    // Verification failed, so createSecureFetch should never be called
    expect(createSecureFetchMock).not.toHaveBeenCalled();
  });
});
