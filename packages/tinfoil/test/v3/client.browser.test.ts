/**
 * The clients in a browser: EHBP is the only transport and the default, TLS
 * is refused with the browser limitation named, the cache secret lives in
 * memory, OpenAI clients take a bearer token, and a sealed streamed response
 * is observed chunk by chunk. The enclave is an EHBP peer behind a mocked
 * fetch, since a page can't start a server.
 */
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verification, type Verifier } from "@tinfoilsh/verifier/v3";
import { Identity } from "ehbp";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createEnclaveHTTPClient, EnclaveHTTPClient, resolveTransportMode, type EnclaveClientSeams } from "../../src/v3/enclave-client.js";
import { ConfigurationError } from "../../src/v3/errors.js";
import { resetEphemeralUserCacheSecretForTests, resolveUserCacheSecret } from "../../src/v3/internal/cachesecret.js";
import { createEnclaveOpenAIClient, createTinfoilClient, EnclaveOpenAIClient, TinfoilClient } from "../../src/v3/openai-client.js";
import type { Fetch } from "../../src/v3/options.js";
import { RouterHTTPClient, type RouterClientSeams } from "../../src/v3/router-client.js";
import * as browserEntry from "../../src/v3/index.browser.js";
import { createEhbpPeer, fetchOf, paced, type EhbpPeer } from "./helpers/ehbp-peer.js";

const ENCLAVE = "enclave.example";
let peer: EhbpPeer;
let sseEnded = false;

function verifier(hpke: string | undefined): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo === "") throw new UsageError("repo required");
    },
    callerAuthorizesConfig: () => false,
    verifyV3At: async () => {
      const material = [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) }, ...(hpke === undefined ? [] : [{ id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke }])];
      return {
        cryptoMaterial: () => material.map((m) => ({ ...m })),
        tlsPublicKeyFP: () => "ab".repeat(32),
        hpkePublicKey: () => hpke,
        codeDigest: () => "11".repeat(32),
        freshnessExpiresAt: () => new Date(Date.now() + 60_000),
      } as unknown as Verification;
    },
  } as unknown as Verifier;
}

const documentFetch: Fetch = async () => new Response(new Uint8Array([1]));

function completion(content: string): unknown {
  return { id: "c", object: "chat.completion", created: 1, model: "test", choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }] };
}

function seams(): EnclaveClientSeams & RouterClientSeams {
  return {
    documentFetch,
    sleep: async () => {},
    ehbp: { fetch: fetchOf(peer) },
    routersFetch: async () => new Response(JSON.stringify([ENCLAVE])),
  };
}

beforeAll(async () => {
  peer = await createEhbpPeer((seen) => {
    if (seen.path === "/sse") {
      sseEnded = false;
      return { headers: { "content-type": "text/event-stream" }, body: paced(["data: a\n\n", "data: b\n\n", "data: c\n\n"], 80, () => (sseEnded = true)) };
    }
    if (seen.path.endsWith("/chat/completions")) {
      return { headers: { "content-type": "application/json" }, body: JSON.stringify(completion(seen.sealed ? "sealed" : "plain")) };
    }
    return { headers: { "content-type": "application/json" }, body: JSON.stringify({ path: seen.path, sealed: seen.sealed, text: new TextDecoder().decode(seen.body) }) };
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the browser entry", () => {
  it("exports the same surface as the Node entry", async () => {
    const node = await import("../../src/v3/index.js");
    expect(Object.keys(browserEntry).sort()).toEqual(Object.keys(node).sort());
  });

  it("defaults to the EHBP transport and refuses TLS, naming the browser limitation", async () => {
    expect(resolveTransportMode(undefined)).toBe("ehbp");
    expect(() => resolveTransportMode("tls")).toThrow(/browsers don't expose/);
    const rejected = browserEntry.EnclaveHTTPClient.create(ENCLAVE, "tinfoilsh/repo", { transportMode: "tls" });
    await expect(rejected).rejects.toBeInstanceOf(browserEntry.ConfigurationError);
    await expect(rejected).rejects.toThrow(/"tls" transport mode pins the server certificate, which browsers don't expose/);
    await expect(browserEntry.RouterHTTPClient.create({ transportMode: "tls" })).rejects.toThrow(/browsers don't expose/);
  });

  it("keeps one in-memory cache secret for the page, without warning", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    resetEphemeralUserCacheSecretForTests();
    const first = await resolveUserCacheSecret(undefined);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(await resolveUserCacheSecret(undefined)).toBe(first);
    expect(await resolveUserCacheSecret("mine")).toBe("mine");
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("EnclaveHTTPClient in a browser", () => {
  it("verifies, seals requests to the enclave's key, and restricts the origin", async () => {
    const client = await createEnclaveHTTPClient(ENCLAVE, "tinfoilsh/repo", { verifier: verifier(peer.publicKeyHex) }, seams());
    expect(client).toBeInstanceOf(EnclaveHTTPClient);
    expect(client.enclave()).toBe(ENCLAVE);
    expect(client.baseURL()).toBe(`https://${ENCLAVE}/`);
    expect(client.current()?.hpkePublicKey()).toBe(peer.publicKeyHex);
    const res = await client.fetch(`https://${ENCLAVE}/echo`, { method: "POST", body: "prompt" });
    expect(await res.json()).toEqual({ path: "/echo", sealed: true, text: "prompt" });
    await expect(client.fetch("https://other.example/echo")).rejects.toThrow(/client is bound to enclave/);
  });

  it("reports an enclave without an EHBP key as an attestation failure", async () => {
    await expect(createEnclaveHTTPClient(ENCLAVE, "tinfoilsh/repo", { verifier: verifier(undefined) }, seams())).rejects.toBeInstanceOf(browserEntry.AttestationError);
  });

  it("replays once after the enclave rotates its key", async () => {
    const stale = await (await Identity.generate()).getPublicKeyHex();
    let verifications = 0;
    const rotating = { ...verifier(peer.publicKeyHex), verifyV3At: (...args: unknown[]) => (verifier(verifications++ === 0 ? stale : peer.publicKeyHex).verifyV3At as (...a: unknown[]) => Promise<Verification>)(...args) } as Verifier;
    const client = await createEnclaveHTTPClient(ENCLAVE, "tinfoilsh/repo", { verifier: rotating }, seams());
    const res = await client.fetch(`https://${ENCLAVE}/echo`, { method: "POST", body: "again" });
    expect((await res.json()).text).toBe("again");
    expect(verifications).toBe(2);
  });

  it("delivers a sealed streamed response chunk by chunk", async () => {
    const client = await createEnclaveHTTPClient(ENCLAVE, "tinfoilsh/repo", { verifier: verifier(peer.publicKeyHex) }, seams());
    const res = await client.fetch(`https://${ENCLAVE}/sse`, { method: "POST", body: "{}" });
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    const first = await reader.read();
    expect(decoder.decode(first.value)).toBe("data: a\n\n");
    expect(sseEnded).toBe(false);
    const second = await reader.read();
    expect(decoder.decode(second.value)).toBe("data: b\n\n");
    expect(sseEnded).toBe(false);
    const third = await reader.read();
    expect(decoder.decode(third.value)).toBe("data: c\n\n");
    expect((await reader.read()).done).toBe(true);
    expect(sseEnded).toBe(true);
  });
});

describe("OpenAI clients in a browser", () => {
  it("refuses a bare API key, as the OpenAI client does, and allows a bearer token", async () => {
    const options = { verifier: verifier(peer.publicKeyHex) };
    await expect(createEnclaveOpenAIClient(ENCLAVE, "tinfoilsh/repo", options, { apiKey: "k" }, seams())).rejects.toThrow(/dangerouslyAllowBrowser/);
    const ai = await createEnclaveOpenAIClient(ENCLAVE, "tinfoilsh/repo", options, { bearerToken: "jwt" }, seams());
    expect(ai).toBeInstanceOf(EnclaveOpenAIClient);
    expect(ai.apiKey).toBe("jwt");
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("sealed");
    const last = peer.seen[peer.seen.length - 1]!;
    expect(last.headers.authorization).toBe("Bearer jwt");
    expect(last.sealed).toBe(true);
    const allowed = await createEnclaveOpenAIClient(ENCLAVE, "tinfoilsh/repo", options, { apiKey: "k", dangerouslyAllowBrowser: true }, seams());
    expect(allowed.apiKey).toBe("k");
  });

  it("creates the recommended client over the discovered router with the cache secret spliced in", async () => {
    const ai = await createTinfoilClient({ bearerToken: "jwt" }, seams(), { verifier: verifier(peer.publicKeyHex) });
    expect(ai).toBeInstanceOf(TinfoilClient);
    expect(ai.httpClient()).toBeInstanceOf(RouterHTTPClient);
    expect(ai.httpClient().enclave()).toBe(ENCLAVE);
    expect(ai.baseURL).toBe(`https://${ENCLAVE}/v1/`);
    const reply = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(reply.choices[0]!.message.content).toBe("sealed");
    const body = JSON.parse(new TextDecoder().decode(peer.seen[peer.seen.length - 1]!.body));
    expect(body.user_cache_secret).toBe(await resolveUserCacheSecret(undefined));
    expect(body.model).toBe("test");
  });
});
