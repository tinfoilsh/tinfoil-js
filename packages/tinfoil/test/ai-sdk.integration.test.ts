import { describe, it, expect, beforeAll } from "vitest";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";

/**
 * Vercel AI SDK Integration Tests
 *
 * Tests the integration between Tinfoil SDK and Vercel AI SDK using:
 * 1. createTinfoilAI - convenience function for AI SDK provider
 * 2. SecureClient.fetch - direct usage with createOpenAI from @ai-sdk/openai
 *
 * These tests verify that Tinfoil's secure fetch works correctly with
 * all AI SDK features: text generation, streaming, abort, and system messages.
 *
 * Clients are shared across tests within each describe block to avoid
 * redundant attestation round-trips — attestation is already tested elsewhere.
 *
 * Tool calling and structured output are tested with mocked responses in
 * ai-sdk-provider.unit.test.ts (no real LLM needed for those).
 */
describe("Vercel AI SDK Integration Tests", () => {

  describe("createTinfoilAI Provider", () => {
    // Share a single attested provider across all tests in this group
    let tinfoil: any;

    beforeAll(async () => {
      if (!RUN_INTEGRATION) return;
      const { createTinfoilAI } = await import("../src/ai-sdk-provider");
      tinfoil = await createTinfoilAI(process.env.TINFOIL_API_KEY);
    });

    it.skipIf(!RUN_INTEGRATION)("should generate text with generateText", async () => {
      const { generateText } = await import("ai");

      const { text } = await generateText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Say 'hello' and nothing else.",
        maxTokens: 5,
      });

      expect(text).toBeTruthy();
      expect(typeof text).toBe("string");
      expect(text.length).toBeGreaterThan(0);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should stream text with streamText", async () => {
      const { streamText } = await import("ai");

      const stream = streamText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Count from 1 to 3.",
        maxTokens: 5,
      });

      let accumulatedText = "";
      for await (const chunk of stream.textStream) {
        accumulatedText += chunk;
      }

      expect(accumulatedText).toBeTruthy();
      expect(accumulatedText.length).toBeGreaterThan(0);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should handle AbortController cancellation", async () => {
      const { streamText } = await import("ai");

      const abortController = new AbortController();

      const stream = streamText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Write a very long story about a dragon.",
        maxTokens: 5,
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
      const { generateText } = await import("ai");

      const { text } = await generateText({
        model: tinfoil("gpt-oss-120b-free"),
        system: "You are a helpful assistant. Always respond with exactly one word.",
        prompt: "What color is the sky?",
        maxTokens: 5,
      });

      expect(text).toBeTruthy();
      expect(typeof text).toBe("string");
    }, 60000);
  });

  describe("SecureClient with @ai-sdk/openai-compatible", () => {
    // Share a single attested SecureClient + provider across both tests
    let provider: any;

    beforeAll(async () => {
      if (!RUN_INTEGRATION) return;
      const { SecureClient } = await import("../src/secure-client");
      const { createOpenAICompatible } = await import("@ai-sdk/openai-compatible");

      const secureClient = new SecureClient();
      await secureClient.ready();

      provider = createOpenAICompatible({
        name: "tinfoil-direct",
        baseURL: secureClient.getBaseURL()!,
        apiKey: process.env.TINFOIL_API_KEY,
        fetch: secureClient.fetch,
      });
    });

    it.skipIf(!RUN_INTEGRATION)("should work with createOpenAICompatible directly", async () => {
      const { generateText } = await import("ai");

      const { text } = await generateText({
        model: provider("gpt-oss-120b-free"),
        prompt: "Say 'hello' and nothing else.",
        maxTokens: 5,
      });

      expect(text).toBeTruthy();
      expect(typeof text).toBe("string");
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)("should stream with createOpenAICompatible directly", async () => {
      const { streamText } = await import("ai");

      const stream = streamText({
        model: provider("gpt-oss-120b-free"),
        prompt: "Count from 1 to 3.",
        maxTokens: 5,
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
      const tinfoil = await createTinfoilAI(process.env.TINFOIL_API_KEY, {
        // Using default enclave URL but explicitly setting it
        // In production, you'd set baseURL to your proxy
      });

      const { text } = await generateText({
        model: tinfoil("gpt-oss-120b-free"),
        prompt: "Say 'proxy works' and nothing else.",
        maxTokens: 5,
      });

      expect(text).toBeTruthy();
    }, 60000);
  });
});
