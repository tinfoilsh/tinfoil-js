import { describe, it, expect, vi } from "vitest";

// Mock SecureClient to avoid network/crypto during unit tests
const secureClientMock = {
  ready: vi.fn(async () => {}),
  getBaseURL: vi.fn(() => "https://example-proxy.invalid/"),
  fetch: vi.fn(async () => new Response()),
};

vi.mock("../src/secure-client", () => {
  return {
    SecureClient: vi.fn(() => secureClientMock),
  };
});

// Mock AI SDK provider factory to validate wiring
const createOpenAICompatibleMock = vi.fn((args: any) => {
  // Return a provider-like function to match AI SDK usage shape
  return (modelId: string) => ({ ...args, modelId });
});

vi.mock("@ai-sdk/openai-compatible", () => {
  return {
    createOpenAICompatible: createOpenAICompatibleMock,
  };
});

describe("createTinfoilAI (unit)", () => {
  it("uses SecureClient.getBaseURL() when baseURL is not provided", async () => {
    const { createTinfoilAI } = await import("../src/ai-sdk-provider");

    const provider = await createTinfoilAI("api-key");

    expect(secureClientMock.ready).toHaveBeenCalledTimes(1);
    expect(secureClientMock.getBaseURL).toHaveBeenCalledTimes(1);

    expect(createOpenAICompatibleMock).toHaveBeenCalledTimes(1);
    expect(createOpenAICompatibleMock).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "tinfoil",
        baseURL: "https://example-proxy.invalid/",
        apiKey: "api-key",
        fetch: secureClientMock.fetch,
      }),
    );

    // Provider is callable
    const model = provider("some-model");
    expect(model.modelId).toBe("some-model");
  });

  it("prefers explicit baseURL over SecureClient.getBaseURL()", async () => {
    const { createTinfoilAI } = await import("../src/ai-sdk-provider");

    secureClientMock.getBaseURL.mockClear();
    createOpenAICompatibleMock.mockClear();

    await createTinfoilAI("api-key", { baseURL: "https://explicit.invalid/" });

    expect(secureClientMock.getBaseURL).not.toHaveBeenCalled();
    expect(createOpenAICompatibleMock).toHaveBeenCalledWith(
      expect.objectContaining({
        baseURL: "https://explicit.invalid/",
      }),
    );
  });

  it("throws if no baseURL can be determined", async () => {
    const { createTinfoilAI } = await import("../src/ai-sdk-provider");

    secureClientMock.getBaseURL.mockReturnValueOnce(undefined as any);

    await expect(createTinfoilAI("api-key")).rejects.toThrow(
      "Unable to determine baseURL for AI SDK provider",
    );
  });
});

