/**
 * The AI SDK provider in a browser against the live router, in Chromium:
 * created with a bearer token, it verifies the router over EHBP and
 * generates text through sealed bodies. The live model reasons before it
 * answers, so the assertion is on the finish reason and on the text only
 * when the model finished its answer. Needs the integration lane and a
 * Tinfoil API key, both compiled into the bundle by the lane's config.
 */
import { generateText } from "ai";
import { describe, expect, it } from "vitest";
import { createTinfoil } from "../src/ai-sdk.js";
import { LIVE_MODEL, LIVE_REPO, SHA256_HEX, TERMINAL_FINISH_REASONS } from "./helpers/live.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const bearerToken = process.env.TINFOIL_API_KEY ?? "";

describe("createTinfoil in a browser on the live router", () => {
  it.skipIf(!RUN_INTEGRATION || bearerToken === "")("verifies the router with a bearer token and generates text", async () => {
    const tinfoil = await createTinfoil({ bearerToken });
    expect(tinfoil.httpClient().repo()).toBe(LIVE_REPO);
    expect(tinfoil.httpClient().current()?.hpkePublicKey()).toMatch(SHA256_HEX);

    const generated = await generateText({ model: tinfoil(LIVE_MODEL), prompt: "Say the single word: pong", maxOutputTokens: 512 });
    expect(TERMINAL_FINISH_REASONS).toContain(generated.finishReason);
    if (generated.finishReason === "stop") expect(generated.text.length).toBeGreaterThan(0);
  });
});
