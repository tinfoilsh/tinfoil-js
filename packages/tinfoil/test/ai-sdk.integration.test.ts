/**
 * The AI SDK provider against the live router: text generation, a streamed
 * answer whose parts arrive before the end, abort, and a system message. The
 * live model reasons before it answers, so the assertions are on the finish
 * reason and on the text only when the model finished its answer.
 */
import { generateText, streamText } from "ai";
import { describe, expect, it } from "vitest";
import { createTinfoil, type TinfoilProvider } from "../src/internal/ai-sdk.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const MODEL = "gpt-oss-120b";
const apiKey = process.env.TINFOIL_API_KEY ?? "";

describe("createTinfoil against the live router", () => {
  let tinfoil: TinfoilProvider;

  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "verifies the router, generates and streams text, aborts, and honours a system message",
    async () => {
      tinfoil = await createTinfoil({ apiKey });
      expect(tinfoil.httpClient().current()?.tlsPublicKeyFP).toMatch(/^[0-9a-f]{64}$/);

      const generated = await generateText({ model: tinfoil(MODEL), prompt: "Say the single word: pong", maxOutputTokens: 512 });
      expect(["stop", "length"]).toContain(generated.finishReason);
      if (generated.finishReason === "stop") expect(generated.text.length).toBeGreaterThan(0);

      const streamed = streamText({ model: tinfoil(MODEL), prompt: "Count from 1 to 20, separated by spaces.", maxOutputTokens: 512 });
      let parts = 0;
      let finished = false;
      for await (const part of streamed.fullStream) {
        expect(finished).toBe(false);
        if (part.type === "text-delta" || part.type === "reasoning-delta") parts++;
        if (part.type === "finish") finished = true;
      }
      expect(parts).toBeGreaterThan(1);
      expect(finished).toBe(true);
      expect(["stop", "length"]).toContain(await streamed.finishReason);

      const controller = new AbortController();
      const aborted = streamText({ model: tinfoil(MODEL), prompt: "Write a very long story about a dragon.", maxOutputTokens: 512, abortSignal: controller.signal });
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

      const system = await generateText({ model: tinfoil(MODEL), system: "Answer with exactly one word.", prompt: "What colour is the sky?", maxOutputTokens: 512 });
      expect(["stop", "length"]).toContain(system.finishReason);
    },
    240_000,
  );
});
