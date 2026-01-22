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
}));

vi.mock("../src/secure-fetch.js", () => ({
  createSecureFetch: createSecureFetchMock,
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
