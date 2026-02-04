import { describe, it, expect, vi } from "vitest";
import { z } from "zod";

// Mock SecureClient to avoid network/crypto during unit tests
const secureClientMock = {
  ready: vi.fn(async () => {}),
  getBaseURL: vi.fn(() => "https://example-proxy.invalid/"),
  fetch: vi.fn(async () => new Response()),
};

vi.mock("../src/secure-client", () => {
  return {
    SecureClient: vi.fn(function () { return secureClientMock; }),
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
  it("throws ConfigurationError when no API key is provided", async () => {
    // Clear TINFOIL_API_KEY so env fallback doesn't kick in
    const saved = process.env.TINFOIL_API_KEY;
    delete process.env.TINFOIL_API_KEY;
    try {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      await expect(createTinfoilAI(undefined)).rejects.toThrow(/API key is required/);
    } finally {
      if (saved !== undefined) process.env.TINFOIL_API_KEY = saved;
    }
  });

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

/**
 * Tests that the Vercel AI SDK correctly handles tool calling and structured
 * output through an OpenAI-compatible provider wired to a mock fetch.
 *
 * These use the real createOpenAICompatible (bypassing the module mock above)
 * with a fake fetch, so they exercise the full AI SDK parsing pipeline without
 * hitting a real model.
 */
describe("AI SDK provider — tool calling & structured output (mocked)", () => {
  /** Helper: build an OpenAI-compatible provider backed by a fake fetch. */
  async function providerWithFetch(fakeFetch: typeof globalThis.fetch) {
    const actual = await vi.importActual<typeof import("@ai-sdk/openai-compatible")>("@ai-sdk/openai-compatible");
    return actual.createOpenAICompatible({
      name: "tinfoil-test",
      baseURL: "https://mock.invalid/v1",
      apiKey: "test-key",
      fetch: fakeFetch,
    });
  }

  /** Helper: wrap a JSON body in a standard Response. */
  function jsonResponse(body: unknown) {
    return new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    });
  }

  it("should handle tool calling through the provider", async () => {
    const { generateText, tool } = await import("ai");

    const cannedResponse = {
      id: "chatcmpl-mock",
      object: "chat.completion",
      created: Date.now(),
      model: "test-model",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: null,
            tool_calls: [
              {
                id: "call_1",
                type: "function",
                function: {
                  name: "weather",
                  arguments: JSON.stringify({ location: "San Francisco" }),
                },
              },
            ],
          },
          finish_reason: "tool_calls",
        },
      ],
      usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
    };

    const fakeFetch = vi.fn(async () => jsonResponse(cannedResponse));
    const provider = await providerWithFetch(fakeFetch as any);

    const { toolCalls } = await generateText({
      model: provider("test-model"),
      prompt: "What is the weather in San Francisco?",
      tools: {
        weather: tool({
          description: "Get weather for a location",
          parameters: z.object({
            location: z.string(),
          }),
          execute: async ({ location }) => ({
            temperature: 72,
            condition: "sunny",
            location,
          }),
        }),
      },
    });

    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].toolName).toBe("weather");
    expect(toolCalls[0].input).toEqual({ location: "San Francisco" });

    // Verify the SDK sent the request through our fetch
    expect(fakeFetch).toHaveBeenCalledTimes(1);
  });

  it("should handle structured output through the provider", async () => {
    const { generateObject } = await import("ai");

    const cannedResponse = {
      id: "chatcmpl-mock",
      object: "chat.completion",
      created: Date.now(),
      model: "test-model",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: JSON.stringify({ name: "Alice", age: 30 }),
          },
          finish_reason: "stop",
        },
      ],
      usage: { prompt_tokens: 10, completion_tokens: 8, total_tokens: 18 },
    };

    const fakeFetch = vi.fn(async () => jsonResponse(cannedResponse));
    const provider = await providerWithFetch(fakeFetch as any);

    const { object } = await generateObject({
      model: provider("test-model"),
      schema: z.object({
        name: z.string(),
        age: z.number(),
      }),
      prompt: "Generate a fictional person.",
    });

    expect(object).toEqual({ name: "Alice", age: 30 });
    expect(typeof object.name).toBe("string");
    expect(typeof object.age).toBe("number");

    // Verify the SDK sent the request through our fetch
    expect(fakeFetch).toHaveBeenCalledTimes(1);
  });
});

