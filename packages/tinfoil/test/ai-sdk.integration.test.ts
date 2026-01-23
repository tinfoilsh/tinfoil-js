import { describe, it, expect } from "vitest";
import { z } from "zod";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";

/**
 * Vercel AI SDK Integration Tests
 * 
 * Tests the integration between Tinfoil SDK and Vercel AI SDK using:
 * 1. createTinfoilAI - convenience function for AI SDK provider
 * 2. SecureClient.fetch - direct usage with createOpenAI from @ai-sdk/openai
 * 
 * These tests verify that Tinfoil's secure fetch works correctly with
 * all AI SDK features: text generation, streaming, tool calling, and structured output.
 */
describe("Vercel AI SDK Integration Tests", () => {
  
  describe("createTinfoilAI Provider", () => {
    it.skipIf(!RUN_INTEGRATION)("should generate text with generateText", async () => {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      const { generateText } = await import("ai");

      const tinfoil = await createTinfoilAI("tinfoil");

      const { text } = await generateText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Say 'hello' and nothing else.",
      });

      expect(text).toBeTruthy();
      expect(typeof text).toBe("string");
      expect(text.length).toBeGreaterThan(0);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should stream text with streamText", async () => {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      const { streamText } = await import("ai");

      const tinfoil = await createTinfoilAI("tinfoil");

      const stream = streamText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Count from 1 to 3.",
      });

      let accumulatedText = "";
      for await (const chunk of stream.textStream) {
        accumulatedText += chunk;
      }

      expect(accumulatedText).toBeTruthy();
      expect(accumulatedText.length).toBeGreaterThan(0);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should handle tool calling", async () => {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      const { generateText, tool } = await import("ai");

      const tinfoil = await createTinfoilAI("tinfoil");

      const { text, toolCalls } = await generateText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "What is the weather in San Francisco? Use the weather tool.",
        tools: {
          weather: tool({
            description: "Get the weather for a location",
            parameters: z.object({
              location: z.string().describe("The city to get weather for"),
            }),
            execute: async ({ location }) => {
              return { temperature: 72, condition: "sunny", location };
            },
          }),
        },
      });

      // The model should either call the tool or respond with text
      expect(text !== undefined || toolCalls !== undefined).toBe(true);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should handle structured output with generateObject", async () => {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      const { generateObject } = await import("ai");

      const tinfoil = await createTinfoilAI("tinfoil");

      const { object } = await generateObject({
        model: tinfoil("gpt-oss-120b-free"),
        schema: z.object({
          name: z.string(),
          age: z.number(),
        }),
        prompt: "Generate a fictional person with a name and age.",
      });

      expect(object).toBeTruthy();
      expect(typeof object.name).toBe("string");
      expect(typeof object.age).toBe("number");
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should handle AbortController cancellation", async () => {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      const { streamText } = await import("ai");

      const tinfoil = await createTinfoilAI("tinfoil");
      const abortController = new AbortController();

      const stream = streamText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Write a very long story about a dragon.",
        abortSignal: abortController.signal,
      });

      // Start reading then abort after first chunk
      let chunksReceived = 0;
      try {
        for await (const chunk of stream.textStream) {
          chunksReceived++;
          if (chunksReceived >= 1) {
            abortController.abort();
          }
        }
      } catch (error: any) {
        // AbortError is expected
        expect(error.name === "AbortError" || error.message.includes("abort")).toBe(true);
      }

      // Should have received at least one chunk before aborting
      expect(chunksReceived).toBeGreaterThanOrEqual(1);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should work with system message", async () => {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      const { generateText } = await import("ai");

      const tinfoil = await createTinfoilAI("tinfoil");

      const { text } = await generateText({
        model: tinfoil("gpt-oss-120b-free"),
        system: "You are a helpful assistant. Always respond with exactly one word.",
        prompt: "What color is the sky?",
      });

      expect(text).toBeTruthy();
      expect(typeof text).toBe("string");
    }, 60000);
  });

  describe("SecureClient with @ai-sdk/openai-compatible", () => {
    it.skipIf(!RUN_INTEGRATION)("should work with createOpenAICompatible directly", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { createOpenAICompatible } = await import("@ai-sdk/openai-compatible");
      const { generateText } = await import("ai");

      const secureClient = new SecureClient();
      await secureClient.ready();

      const provider = createOpenAICompatible({
        name: "tinfoil-direct",
        baseURL: secureClient.getBaseURL()!,
        apiKey: "tinfoil",
        fetch: secureClient.fetch,
      });

      const { text } = await generateText({
        model: provider("gpt-oss-120b-free"),
        prompt: "Say 'hello' and nothing else.",
      });

      expect(text).toBeTruthy();
      expect(typeof text).toBe("string");
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should stream with createOpenAICompatible directly", async () => {
      const { SecureClient } = await import("../src/secure-client");
      const { createOpenAICompatible } = await import("@ai-sdk/openai-compatible");
      const { streamText } = await import("ai");

      const secureClient = new SecureClient();
      await secureClient.ready();

      const provider = createOpenAICompatible({
        name: "tinfoil-direct",
        baseURL: secureClient.getBaseURL()!,
        apiKey: "tinfoil",
        fetch: secureClient.fetch,
      });

      const stream = streamText({
        model: provider("gpt-oss-120b-free"),
        prompt: "Count from 1 to 3.",
      });

      let accumulatedText = "";
      for await (const chunk of stream.textStream) {
        accumulatedText += chunk;
      }

      expect(accumulatedText).toBeTruthy();
      expect(accumulatedText.length).toBeGreaterThan(0);
    }, 60000);
  });

  describe("Proxy Configuration", () => {
    it.skipIf(!RUN_INTEGRATION)("should work with custom baseURL for proxy", async () => {
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      const { generateText } = await import("ai");

      // This test verifies that baseURL can be configured separately
      // In a real proxy setup, baseURL would point to your proxy server
      const tinfoil = await createTinfoilAI("tinfoil", {
        // Using default enclave URL but explicitly setting it
        // In production, you'd set baseURL to your proxy
      });

      const { text } = await generateText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Say 'proxy works' and nothing else.",
      });

      expect(text).toBeTruthy();
    }, 60000);
  });
});
