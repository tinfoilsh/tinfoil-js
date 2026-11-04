/**
 * The enclave clients against a live enclave, in both transport modes: a
 * verified client, a chat completion, and a streamed completion whose
 * chunks arrive before the stream ends. Runs in the integration lane with
 * a Tinfoil API key.
 */
import { describe, expect, it } from "vitest";
import { EnclaveHTTPClient } from "../../src/v3/enclave-client.js";
import { EnclaveOpenAIClient } from "../../src/v3/openai-client.js";
import type { TransportMode } from "../../src/v3/options.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const HOST = "inference.tinfoil.sh";
const REPO = "tinfoilsh/confidential-model-router";
const MODEL = "gpt-oss-120b";
const apiKey = process.env.TINFOIL_API_KEY ?? "";

describe.each<TransportMode>(["tls", "ehbp"])("EnclaveHTTPClient against %s on a live enclave", (transportMode) => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "verifies, completes a chat, and streams a completion chunk by chunk",
    async () => {
      const http = await EnclaveHTTPClient.create(HOST, REPO, { transportMode });
      expect(http.enclave()).toBe(HOST);
      expect(http.current()?.tlsPublicKeyFP()).toMatch(/^[0-9a-f]{64}$/);

      const ai = await EnclaveOpenAIClient.create(HOST, REPO, { transportMode }, { apiKey });
      expect(ai.baseURL).toBe(`https://${HOST}/v1/`);
      const reply = await ai.chat.completions.create({ model: MODEL, messages: [{ role: "user", content: "Say the single word: pong" }], max_tokens: 20 });
      expect(reply.choices[0]!.message.content).toBeTruthy();

      const stream = await ai.chat.completions.create({ model: MODEL, messages: [{ role: "user", content: "Count from 1 to 20, separated by spaces." }], stream: true, max_tokens: 80 });
      let chunks = 0;
      let text = "";
      let finished = false;
      for await (const chunk of stream) {
        expect(finished).toBe(false);
        chunks++;
        text += chunk.choices[0]?.delta?.content ?? "";
        if (chunk.choices[0]?.finish_reason) finished = true;
      }
      expect(chunks).toBeGreaterThan(1);
      expect(text.length).toBeGreaterThan(0);
    },
    180_000,
  );
});
