/**
 * The client under Bun against the live router: a router client discovers
 * and verifies a router without a credential, and an OpenAI client completes
 * a chat over each transport, TLS pinned to the attested key and EHBP sealed
 * to it. Needs the integration lane; the completions need a Tinfoil API key
 * too. Run with: RUN_TINFOIL_INTEGRATION=true bun test test/integration.bun.ts
 */
import { describe, expect, it } from "bun:test";
import { RouterHTTPClient } from "../src/index.js";
import type { Transport } from "../src/options.js";
import { completeChat, SHA256_HEX } from "./helpers/live.js";
import { openAIOver } from "./helpers/openai.js";
import { lastFacts } from "./helpers/report.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const apiKey = process.env.TINFOIL_API_KEY ?? "";

describe("RouterHTTPClient under Bun on the live router", () => {
  it.skipIf(!RUN_INTEGRATION)(
    "discovers and verifies a router",
    async () => {
      const http = await RouterHTTPClient.create();
      expect(lastFacts(http)?.tlsPublicKeyFP).toMatch(SHA256_HEX);
      expect(lastFacts(http)?.hpkePublicKey).toMatch(SHA256_HEX);
    },
    180_000,
  );
});

for (const transportMode of ["tls", "ehbp"] as const satisfies readonly Transport["kind"][]) {
  describe(`OpenAIClient<RouterHTTPClient> under Bun over ${transportMode} on the live router`, () => {
    it.skipIf(!RUN_INTEGRATION || apiKey === "")(
      "verifies a router and completes a chat through it",
      async () => {
        const ai = await openAIOver(RouterHTTPClient.create({ transport: { kind: transportMode } }), { apiKey });
        const router = ai.httpClient;
        expect(ai.baseURL).toBe(`https://${router.enclave}/v1/`);
        const completed = await completeChat(ai);
        expect(completed.finishReason).toBeTruthy();
      },
      180_000,
    );
  });
}
