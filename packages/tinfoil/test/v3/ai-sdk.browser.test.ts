/**
 * The AI SDK provider in a browser: created with a bearer token over the
 * EHBP peer behind a mocked fetch, generating text through sealed bodies and
 * streaming an answer chunk by chunk.
 */
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verification, type Verifier } from "@tinfoilsh/verifier/v3";
import { generateText, streamText } from "ai";
import { beforeAll, describe, expect, it } from "vitest";
import { createTinfoilAIProvider, type TinfoilAIProvider } from "../../src/v3/ai-sdk.js";
import { ConfigurationError } from "../../src/v3/errors.js";
import type { Fetch } from "../../src/v3/options.js";
import * as browserEntry from "../../src/v3/index.browser.js";
import { createEhbpPeer, fetchOf, paced, type EhbpPeer } from "./helpers/ehbp-peer.js";

const ENCLAVE = "enclave.example";
const MODEL = "test-model";
let peer: EhbpPeer;
let sseEnded = false;

function verifier(hpke: string): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo === "") throw new UsageError("repo required");
    },
    callerAuthorizesConfig: () => false,
    verifyV3At: async () =>
      ({
        cryptoMaterial: () => [
          { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) },
          { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke },
        ],
        tlsPublicKeyFP: () => "ab".repeat(32),
        hpkePublicKey: () => hpke,
        codeDigest: () => "11".repeat(32),
        freshnessExpiresAt: () => new Date(Date.now() + 60_000),
      }) as unknown as Verification,
  } as unknown as Verifier;
}

const chunk = (delta: Record<string, unknown>, finishReason: string | null = null): string =>
  `data: ${JSON.stringify({ id: "c", object: "chat.completion.chunk", created: 1, model: MODEL, choices: [{ index: 0, delta, finish_reason: finishReason }] })}\n\n`;

beforeAll(async () => {
  peer = await createEhbpPeer((seen) => {
    const request = JSON.parse(new TextDecoder().decode(seen.body)) as { stream?: boolean };
    if (request.stream === true) {
      sseEnded = false;
      return { headers: { "content-type": "text/event-stream" }, body: paced([chunk({ content: "one" }), chunk({ content: " two" }), chunk({}, "stop"), "data: [DONE]\n\n"], 80, () => (sseEnded = true)) };
    }
    return {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: "c", object: "chat.completion", created: 1, model: MODEL, choices: [{ index: 0, message: { role: "assistant", content: seen.sealed ? "sealed" : "plain" }, finish_reason: "stop" }] }),
    };
  });
});

describe("createTinfoilAI in a browser", () => {
  let tinfoil: TinfoilAIProvider;

  beforeAll(async () => {
    const documentFetch: Fetch = async () => new Response(new Uint8Array([1]));
    tinfoil = await createTinfoilAIProvider(
      { bearerToken: "short-lived", enclave: { host: ENCLAVE, repo: "tinfoilsh/repo" }, verifier: verifier(peer.publicKeyHex) },
      { documentFetch, sleep: async () => {}, ehbp: { fetch: fetchOf(peer) } },
    );
  });

  it("is exported by the browser entry and refuses the TLS transport", async () => {
    expect(typeof browserEntry.createTinfoilAI).toBe("function");
    await expect(browserEntry.createTinfoilAI({ bearerToken: "t", transportMode: "tls" })).rejects.toBeInstanceOf(ConfigurationError);
  });

  it("generates text through sealed requests carrying the bearer token", async () => {
    const { text } = await generateText({ model: tinfoil(MODEL), prompt: "Say pong", maxRetries: 0 });
    expect(text).toBe("sealed");
    const seen = peer.seen[peer.seen.length - 1]!;
    expect(seen.sealed).toBe(true);
    expect(seen.headers["authorization"]).toBe("Bearer short-lived");
    expect(tinfoil.httpClient().enclave()).toBe(ENCLAVE);
  });

  it("streams an answer chunk by chunk before the stream ends", async () => {
    const result = streamText({ model: tinfoil(MODEL), prompt: "Count", maxRetries: 0 });
    const deltas: string[] = [];
    let endedAtFirstDelta: boolean | undefined;
    for await (const delta of result.textStream) {
      if (endedAtFirstDelta === undefined) endedAtFirstDelta = sseEnded;
      deltas.push(delta);
    }
    expect(endedAtFirstDelta).toBe(false);
    expect(deltas.join("")).toBe("one two");
  });
});
