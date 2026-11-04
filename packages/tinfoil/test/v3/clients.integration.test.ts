/**
 * The enclave, router and gateway clients against live services: a verified
 * client, a chat completion, and a streamed completion whose chunks arrive
 * before the final one. The catalog and verification tests need only the
 * integration lane; completions need a Tinfoil API key too. The live model
 * reasons before it answers, so the assertions are on the completion's
 * shape and its terminal finish reason, and on the text only when the model
 * finished its answer.
 */
import { describe, expect, it } from "vitest";
import type OpenAI from "openai";
import { EnclaveHTTPClient } from "../../src/v3/enclave-client.js";
import { fetchCatalog, GatewayHTTPClient } from "../../src/v3/gateway-client.js";
import { createClient, EnclaveOpenAIClient, GatewayOpenAIClient, RouterOpenAIClient } from "../../src/v3/openai-client.js";
import type { TransportMode } from "../../src/v3/options.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const HOST = "inference.tinfoil.sh";
const REPO = "tinfoilsh/confidential-model-router";
const MODEL = "gpt-oss-120b";
const GATEWAY_HOST = "inference-gateway.tinfoil.sh";
const apiKey = process.env.TINFOIL_API_KEY ?? "";

/**
 * Completes one chat through `ai`, checking the reply's shape. A reasoning
 * model may put its whole answer in a reasoning field and finish with empty
 * content, so a finished reply must carry text in either.
 */
export async function completeChat(ai: OpenAI, model = MODEL): Promise<void> {
  const reply = await ai.chat.completions.create({ model, messages: [{ role: "user", content: "Say the single word: pong" }], max_tokens: 512 });
  expect(reply.choices.length).toBeGreaterThan(0);
  const choice = reply.choices[0]!;
  expect(choice.message.role).toBe("assistant");
  expect(["stop", "length"]).toContain(choice.finish_reason);
  const message = choice.message as { content?: string | null; reasoning?: string | null; reasoning_content?: string | null };
  if (choice.finish_reason === "stop") expect(message.content || message.reasoning || message.reasoning_content).toBeTruthy();
}

/** Streams one chat through `ai`, checking that chunks arrive before the final one and that it is terminal. */
export async function streamChat(ai: OpenAI, model = MODEL): Promise<void> {
  const stream = await ai.chat.completions.create({ model, messages: [{ role: "user", content: "Count from 1 to 20, separated by spaces." }], stream: true, max_tokens: 512 });
  let deltas = 0;
  let finishReason: string | undefined;
  for await (const chunk of stream) {
    expect(finishReason).toBeUndefined();
    const delta = chunk.choices[0]?.delta as { content?: string | null; reasoning?: string | null } | undefined;
    if (delta?.content || delta?.reasoning) deltas++;
    if (chunk.choices[0]?.finish_reason) finishReason = chunk.choices[0].finish_reason;
  }
  expect(deltas).toBeGreaterThan(1);
  expect(["stop", "length"]).toContain(finishReason);
}

describe.each<TransportMode>(["tls", "ehbp"])("EnclaveHTTPClient against %s on a live enclave", (transportMode) => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "verifies, completes a chat, and streams a completion chunk by chunk",
    async () => {
      const http = await EnclaveHTTPClient.create(HOST, REPO, { transportMode });
      expect(http.enclave()).toBe(HOST);
      expect(http.current()?.tlsPublicKeyFP()).toMatch(/^[0-9a-f]{64}$/);

      const ai = await EnclaveOpenAIClient.create(HOST, REPO, { transportMode }, { apiKey });
      expect(ai.baseURL).toBe(`https://${HOST}/v1/`);
      await completeChat(ai);
      await streamChat(ai);
    },
    180_000,
  );
});

describe.each<TransportMode>(["tls", "ehbp"])("RouterOpenAIClient against %s on the live router", (transportMode) => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "discovers and verifies a router and completes a chat through it",
    async () => {
      const ai = await RouterOpenAIClient.create({ transportMode }, { apiKey });
      const router = ai.httpClient();
      expect(router.repo()).toBe(REPO);
      expect(router.current()?.tlsPublicKeyFP()).toMatch(/^[0-9a-f]{64}$/);
      expect(ai.baseURL).toBe(`https://${router.enclave()}/v1/`);
      await completeChat(ai);
    },
    180_000,
  );
});

describe("createClient on the live router", () => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "completes a chat through the recommended route",
    async () => {
      await completeChat(await createClient({ apiKey }));
    },
    180_000,
  );
});

describe("GatewayHTTPClient on the live gateway", () => {
  it.skipIf(!RUN_INTEGRATION)(
    "reads the catalog and verifies a replica of a listed model through the gateway",
    async () => {
      const catalog = await fetchCatalog(GATEWAY_HOST);
      expect(catalog.size).toBeGreaterThan(0);
      const http = await GatewayHTTPClient.create();
      const models = await http.models();
      expect(models).toEqual([...catalog.keys()].sort());
      const verification = await http.ensureVerified(models[0]!);
      expect(verification.hpkePublicKey()).toMatch(/^[0-9a-f]{64}$/);
      expect(http.current().map((r) => r.reference)).toEqual([catalog.get(models[0]!)!.repo]);
    },
    180_000,
  );

  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "completes a chat through the gateway",
    async () => {
      const ai = await GatewayOpenAIClient.create({}, { apiKey });
      await completeChat(ai, (await ai.httpClient().models())[0]!);
      expect(ai.httpClient().current().length).toBeGreaterThan(0);
    },
    180_000,
  );
});
