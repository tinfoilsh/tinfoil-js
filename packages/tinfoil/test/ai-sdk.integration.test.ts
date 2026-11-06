/**
 * The AI SDK provider against the live router: text generation, a streamed
 * answer whose parts arrive before the end, abort, and a system message. The
 * live model reasons before it answers, so the assertions are on the finish
 * reason and on the text only when the model finished its answer. The
 * attested client under the provider is closed at the end of the test.
 */
import { generateText, streamText } from "ai";
import { describe, expect, it } from "vitest";
import { createTinfoil } from "../src/internal/ai-sdk.js";
import { LIVE_MODEL, SHA256_HEX, TERMINAL_FINISH_REASONS } from "./helpers/live.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const apiKey = process.env.TINFOIL_API_KEY ?? "";
/** Enough for the model's reasoning and a short answer. */
const MAX_OUTPUT_TOKENS = 512;

describe("createTinfoil against the live router", () => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "verifies the router, generates and streams text, aborts, and honours a system message",
    async () => {
      const tinfoil = await createTinfoil({ apiKey });
      await using client = tinfoil.httpClient;
      expect(client.current?.tlsPublicKeyFP).toMatch(SHA256_HEX);

      const generated = await generateText({ model: tinfoil(LIVE_MODEL), prompt: "Say the single word: pong", maxOutputTokens: MAX_OUTPUT_TOKENS });
      expect(TERMINAL_FINISH_REASONS).toContain(generated.finishReason);
      if (generated.finishReason === "stop") expect(generated.text.length).toBeGreaterThan(0);

      const streamed = streamText({ model: tinfoil(LIVE_MODEL), prompt: "Count from 1 to 20, separated by spaces.", maxOutputTokens: MAX_OUTPUT_TOKENS });
      let parts = 0;
      let finished = false;
      for await (const part of streamed.fullStream) {
        expect(finished).toBe(false);
        if (part.type === "text-delta" || part.type === "reasoning-delta") parts++;
        if (part.type === "finish") finished = true;
      }
      expect(parts).toBeGreaterThan(1);
      expect(finished).toBe(true);
      expect(TERMINAL_FINISH_REASONS).toContain(await streamed.finishReason);

      const controller = new AbortController();
      const aborted = streamText({ model: tinfoil(LIVE_MODEL), prompt: "Write a very long story about a dragon.", maxOutputTokens: MAX_OUTPUT_TOKENS, abortSignal: controller.signal });
      let before = 0;
      await expect(
        (async () => {
          for await (const part of aborted.fullStream) {
            if (part.type === "text-delta" || part.type === "reasoning-delta") before++;
            if (before >= 1) controller.abort();
          }
        })(),
      ).rejects.toThrow(/abort/i);
      expect(before).toBeGreaterThanOrEqual(1);

      // The system message limits the answer to one word. The answer is
      // checked only when the model finished it: a budget that ran out says
      // nothing about whether the instruction reached the model.
      const system = await generateText({ model: tinfoil(LIVE_MODEL), system: "Answer with exactly one word.", prompt: "What colour is the sky?", maxOutputTokens: MAX_OUTPUT_TOKENS });
      expect(TERMINAL_FINISH_REASONS).toContain(system.finishReason);
      if (system.finishReason === "stop") {
        const words = system.text.trim().replace(/[.!]+$/, "").split(/\s+/);
        expect(words).toHaveLength(1);
        expect(words[0]).not.toBe("");
      }
    },
    240_000,
  );
});
