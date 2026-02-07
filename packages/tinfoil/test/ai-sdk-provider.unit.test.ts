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

  it("passes explicit baseURL to SecureClient which resolves it via getBaseURL()", async () => {
    const { createTinfoilAI } = await import("../src/ai-sdk-provider");

    secureClientMock.getBaseURL.mockClear();
    createOpenAICompatibleMock.mockClear();

    // When explicit baseURL is provided, SecureClient uses it as resolvedBaseURL
    secureClientMock.getBaseURL.mockReturnValueOnce("https://explicit.invalid/");

    await createTinfoilAI("api-key", { baseURL: "https://explicit.invalid/" });

    expect(createOpenAICompatibleMock).toHaveBeenCalledWith(
      expect.objectContaining({
        baseURL: "https://explicit.invalid/",
      }),
    );
  });
});

