/**
 * The browser build against the live router, in Chromium: the recommended
 * client discovers and verifies a router over EHBP, the only transport a
 * page has, with a bearer token as its credential, then completes a chat and
 * streams a completion chunk by chunk through sealed bodies. Needs the
 * integration lane and a Tinfoil API key, both compiled into the bundle by
 * the lane's config.
 */
import { describe, expect, it } from "vitest";
import { createClient, RouterHTTPClient, TinfoilClient } from "../src/index.browser.js";
import { completeChat, LIVE_REPO, SHA256_HEX, streamChat } from "./helpers/live.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const bearerToken = process.env.TINFOIL_API_KEY ?? "";

describe("the browser build on the live router", () => {
  it.skipIf(!RUN_INTEGRATION || bearerToken === "")("verifies the router over EHBP with a bearer token, completes a chat and streams a completion", async () => {
    const ai = await createClient({ bearerToken });
    expect(ai).toBeInstanceOf(TinfoilClient);
    const router = ai.httpClient();
    expect(router).toBeInstanceOf(RouterHTTPClient);
    expect(router.repo()).toBe(LIVE_REPO);
    expect(router.current()?.hpkePublicKey()).toMatch(SHA256_HEX);
    expect(ai.baseURL).toBe(`https://${router.enclave()}/v1/`);

    const completed = await completeChat(ai);
    expect(completed.finishReason).toBeTruthy();
    const streamed = await streamChat(ai);
    expect(streamed.deltas).toBeGreaterThan(1);
  });
});
