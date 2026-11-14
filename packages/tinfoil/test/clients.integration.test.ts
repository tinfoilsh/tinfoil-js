/**
 * The enclave, router and gateway clients against live services: a verified
 * client, a chat completion, and a streamed completion whose chunks arrive
 * before the final one. The catalog and verification tests need only the
 * integration lane; completions need a Tinfoil API key too. The requests and
 * their checks are the live helpers shared with the browser and Bun lanes.
 * Each client is closed at the end of its test, so a test leaves no pooled
 * connections behind.
 */
import { describe, expect, it } from "vitest";
import { EnclaveHTTPClient } from "../src/enclave-client.js";
import { fetchCatalog, GatewayHTTPClient } from "../src/gateway-client.js";
import { createClient, EnclaveOpenAIClient, GatewayOpenAIClient, RouterOpenAIClient } from "../src/openai-client.js";
import type { TransportMode } from "../src/options.js";
import { completeChat, LIVE_HOST as HOST, LIVE_PIN as PIN, SHA256_HEX, streamChat } from "./helpers/live.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const GATEWAY_HOST = "inference-gateway.tinfoil.sh";
const apiKey = process.env.TINFOIL_API_KEY ?? "";

describe.each<TransportMode>(["tls", "ehbp"])("EnclaveHTTPClient against %s on a live enclave", (transportMode) => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "verifies, completes a chat, and streams a completion chunk by chunk",
    async () => {
      await using http = await EnclaveHTTPClient.create(HOST, PIN, { transportMode });
      expect(http.enclave).toBe(HOST);
      expect(http.current?.tlsPublicKeyFP).toMatch(SHA256_HEX);

      await using ai = await EnclaveOpenAIClient.create(HOST, PIN, { transportMode }, { apiKey });
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
      await using ai = await RouterOpenAIClient.create({ transportMode }, { apiKey });
      const router = ai.httpClient;
      expect(router.pin).toEqual(PIN);
      expect(router.current?.tlsPublicKeyFP).toMatch(SHA256_HEX);
      expect(ai.baseURL).toBe(`https://${router.enclave}/v1/`);
      await completeChat(ai);
    },
    180_000,
  );
});

describe("createClient on the live router", () => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "completes a chat through the recommended route",
    async () => {
      await using ai = await createClient({ apiKey });
      await completeChat(ai);
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
      await using http = await GatewayHTTPClient.create();
      const models = await http.models();
      expect(models).toEqual([...catalog.keys()].sort());
      const verification = await http.ensureVerified(models[0]!);
      expect(verification.hpkePublicKey).toMatch(SHA256_HEX);
      expect(http.current.map((r) => r.reference)).toEqual([catalog.get(models[0]!)!.repo]);
    },
    180_000,
  );

  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "completes a chat through the gateway",
    async () => {
      await using ai = await GatewayOpenAIClient.create({}, { apiKey });
      await completeChat(ai, (await ai.httpClient.models())[0]!);
      expect(ai.httpClient.current.length).toBeGreaterThan(0);
    },
    180_000,
  );
});
