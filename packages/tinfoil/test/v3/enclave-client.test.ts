/**
 * The enclave clients on local servers: option checks before any network
 * I/O, verification before the factory returns, both transport modes, a
 * proxy in front, the verification facts, the replay after a key rotation,
 * and the OpenAI client bound to the attested fetch.
 */
import { Identity } from "ehbp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createEnclaveHTTPClient, EnclaveHTTPClient, resolveTransportMode, type EnclaveClientSeams } from "../../src/v3/enclave-client.js";
import { checkTransportMode, defaultTransportMode, isServerRuntime } from "../../src/v3/internal/platform.js";
import { AttestationError, ConfigurationError } from "../../src/v3/errors.js";
import { createEnclaveOpenAIClient, EnclaveOpenAIClient } from "../../src/v3/openai-client.js";
import type { EnclaveOptions, Fetch } from "../../src/v3/options.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, type Verification, type Verifier } from "../../../verifier/src/index.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";
import { paced, startTlsServer, TEST_CERT, TEST_PIN, type TlsServer } from "./helpers/tls-server.js";

let tls: TlsServer;
let ehbp: EhbpServer;
let sseEnded = false;

/** A verifier whose verifications carry the given keys; `keys` is read per verification so a test can rotate them. */
function verifier(keys: () => { tls?: string; hpke?: string }): Verifier {
  return {
    checkRepoVerifiability: (repo: string) => {
      if (repo.includes(" ")) throw new UsageError(`bad repo ${repo}`);
    },
    verifyV3At: async () => {
      const k = keys();
      const material = [
        ...(k.tls === undefined ? [] : [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: k.tls }]),
        ...(k.hpke === undefined ? [] : [{ id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: k.hpke }]),
      ];
      return {
        cryptoMaterial: () => material.map((m) => ({ ...m })),
        tlsPublicKeyFP: () => k.tls,
        hpkePublicKey: () => k.hpke,
        codeDigest: () => "11".repeat(32),
        freshnessExpiresAt: () => new Date(Date.now() + 60_000),
      } as unknown as Verification;
    },
  } as unknown as Verifier;
}

/** A document fetch that answers any attestation request and counts the calls. */
function documents(): { fetch: Fetch; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetch: async (input) => {
      calls.push(String(input));
      return new Response(new Uint8Array([1]));
    },
  };
}

beforeAll(async () => {
  tls = await startTlsServer((seen) => {
    if (seen.path === "/sse") {
      sseEnded = false;
      return { headers: { "content-type": "text/event-stream" }, body: paced(["data: a\n\n", "data: b\n\n"], 60, () => (sseEnded = true)) };
    }
    if (seen.path === "/v1/chat/completions") {
      return { headers: { "content-type": "application/json" }, body: JSON.stringify(completion("pinned")) };
    }
    return { headers: { "content-type": "application/json" }, body: JSON.stringify({ path: seen.path, enclave: seen.headers["x-tinfoil-enclave-url"] ?? null }) };
  });
  ehbp = await startEhbpServer((seen) => {
    if (seen.path === "/chat/completions" || seen.path === "/v1/chat/completions") {
      return { headers: { "content-type": "application/json" }, body: JSON.stringify(completion(new TextDecoder().decode(seen.body).length > 0 ? "sealed" : "plain")) };
    }
    return {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path: seen.path, sealed: seen.sealed, enclave: seen.headers["x-tinfoil-enclave-url"] ?? null, text: new TextDecoder().decode(seen.body) }),
    };
  });
});

afterAll(async () => {
  await Promise.all([tls.close(), ehbp.close()]);
});

function completion(content: string): unknown {
  return {
    id: "chatcmpl-1",
    object: "chat.completion",
    created: 1,
    model: "test",
    choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
  };
}

describe("EnclaveHTTPClient.create", () => {
  it("defaults the transport mode by platform and rejects an unknown one", () => {
    expect(resolveTransportMode(undefined)).toBe("tls");
    expect(resolveTransportMode("ehbp")).toBe("ehbp");
    expect(() => resolveTransportMode("quic" as never)).toThrow(/unknown transport mode "quic"/);
  });

  it("treats only a runtime that identifies itself as Node or Bun as a server, and anything else as a browser", () => {
    expect(isServerRuntime({ process: { versions: { node: "22.0.0" } } })).toBe(true);
    expect(isServerRuntime({ process: { versions: { bun: "1.2.0" } } })).toBe(true);
    expect(isServerRuntime({ Bun: {} })).toBe(true);
    // A worker has neither window nor document, only self; it is a browser all the same.
    const worker = { self: {} } as unknown as Parameters<typeof isServerRuntime>[0];
    expect(isServerRuntime(worker)).toBe(false);
    expect(defaultTransportMode(worker)).toBe("ehbp");
    expect(() => checkTransportMode("tls", worker)).toThrow(/browsers don't expose/);
    expect(() => checkTransportMode("ehbp", worker)).not.toThrow();
    expect(isServerRuntime({ process: { versions: {} } })).toBe(false);
  });

  it("checks its options before fetching anything", async () => {
    const docs = documents();
    const seams: EnclaveClientSeams = { documentFetch: docs.fetch };
    const v = verifier(() => ({ tls: TEST_PIN }));
    const cases: [string, string, EnclaveOptions][] = [
      ["", "tinfoilsh/repo", { verifier: v }],
      ["enclave.example", "tinfoilsh/repo", { verifier: v, transportMode: "quic" as never }],
      ["enclave.example", "tinfoilsh/repo", { verifier: v, baseURL: "http://proxy.example/" }],
      ["enclave.example", "tinfoilsh/repo", { verifier: v, baseURL: "https://proxy.example/" }],
      ["enclave.example", "tinfoilsh/repo", { verifier: v, transportMode: "tls", baseURL: "https://proxy.example/" }],
      ["enclave.example", "bad repo", { verifier: v }],
    ];
    for (const [host, repo, options] of cases) {
      await expect(createEnclaveHTTPClient(host, repo, options, seams), `${host} ${repo}`).rejects.toBeInstanceOf(ConfigurationError);
    }
    expect(docs.calls).toHaveLength(0);
  });

  it("verifies before returning and reports a failed verification without constructing the client", async () => {
    const docs = documents();
    const pending = createEnclaveHTTPClient(tls.host, "tinfoilsh/repo", { verifier: verifier(() => ({})), transportMode: "tls" }, { documentFetch: docs.fetch, sleep: async () => {} });
    await expect(pending).rejects.toBeInstanceOf(AttestationError);
    expect(docs.calls.length).toBe(2);
  });
});

describe("EnclaveHTTPClient over TLS", () => {
  let client: EnclaveHTTPClient;
  let docs: ReturnType<typeof documents>;

  beforeAll(async () => {
    docs = documents();
    client = await createEnclaveHTTPClient(
      tls.host,
      "tinfoilsh/repo",
      { verifier: verifier(() => ({ tls: TEST_PIN })), transportMode: "tls" },
      { documentFetch: docs.fetch, tls: { ca: TEST_CERT } },
    );
  });

  it("is verified on creation and exposes the facts", async () => {
    expect(docs.calls).toEqual([`https://${tls.host}/.well-known/tinfoil-attestation?nonce=${docs.calls[0]!.split("nonce=")[1]}`]);
    expect(client.enclave()).toBe(tls.host);
    expect(client.repo()).toBe("tinfoilsh/repo");
    expect(client.baseURL()).toBe(`https://${tls.host}/`);
    expect(client.current()?.tlsPublicKeyFP()).toBe(TEST_PIN);
    expect((await client.ensureVerified()).codeDigest()).toBe("11".repeat(32));
    expect(docs.calls).toHaveLength(1);
    await client.reverify();
    expect(docs.calls).toHaveLength(2);
  });

  it("sends over the pinned connection, refuses other origins and plaintext, and omits the proxy header", async () => {
    const res = await client.fetch(`${tls.origin}/models`);
    expect(await res.json()).toEqual({ path: "/models", enclave: null });
    await expect(client.fetch("https://other.example/models")).rejects.toThrow(/client is bound to enclave/);
    await expect(client.fetch(`http://${tls.host}/models`)).rejects.toBeInstanceOf(ConfigurationError);
  });

  it("streams a response as the server writes it", async () => {
    const res = await client.fetch(`${tls.origin}/sse`);
    const reader = res.body!.getReader();
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toBe("data: a\n\n");
    expect(sseEnded).toBe(false);
    await reader.cancel();
  });

  it("backs an OpenAI client on the enclave's /v1/ API over the pinned connection", async () => {
    const ai = await createEnclaveOpenAIClient(
      tls.host,
      "tinfoilsh/repo",
      { verifier: verifier(() => ({ tls: TEST_PIN })), transportMode: "tls" },
      { apiKey: "k" },
      { documentFetch: docs.fetch, tls: { ca: TEST_CERT } },
    );
    expect(ai.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(ai.httpClient()).toBeInstanceOf(EnclaveHTTPClient);
    const completion = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(completion.choices[0]!.message.content).toBe("pinned");
    expect(tls.seen[tls.seen.length - 1]!.headers.authorization).toBe("Bearer k");
    expect(() => new (EnclaveOpenAIClient as unknown as new (...a: unknown[]) => unknown)(Symbol("x"), ai.httpClient(), {})).toThrow(ConfigurationError);
  });

  it("keeps the attested transport and its own settings through option changes and clones", async () => {
    const ai = await createEnclaveOpenAIClient(
      tls.host,
      "tinfoilsh/repo",
      { verifier: verifier(() => ({ tls: TEST_PIN })), transportMode: "tls" },
      { apiKey: "k", timeout: 1234, maxRetries: 0, defaultHeaders: { "x-custom": "kept" }, dangerouslyAllowBrowser: true },
      { documentFetch: docs.fetch, tls: { ca: TEST_CERT } },
    );
    const evil: Fetch = async () => new Response("intercepted");
    const fetchOf = (client: unknown): Fetch => (client as { fetch: Fetch }).fetch;
    expect(() => ((ai as unknown as { fetch: Fetch }).fetch = evil)).toThrow(TypeError);
    expect(() => ((ai as unknown as { baseURL: string }).baseURL = "https://evil.example/")).toThrow(TypeError);
    const clone = ai.withOptions({ apiKey: "k2", baseURL: "https://evil.example/", fetch: evil } as Parameters<typeof ai.withOptions>[0]);
    expect(clone).toBeInstanceOf(EnclaveOpenAIClient);
    expect(clone.httpClient()).toBe(ai.httpClient());
    expect(clone.baseURL).toBe(`https://${tls.host}/v1/`);
    expect(fetchOf(clone)).toBe(fetchOf(ai));
    expect(clone.timeout).toBe(1234);
    expect(clone.maxRetries).toBe(0);
    expect((clone as unknown as { _options: { dangerouslyAllowBrowser?: boolean } })._options.dangerouslyAllowBrowser).toBe(true);
    const completion = await clone.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(completion.choices[0]!.message.content).toBe("pinned");
    expect(tls.seen[tls.seen.length - 1]!.headers.authorization).toBe("Bearer k2");
    expect(tls.seen[tls.seen.length - 1]!.headers["x-custom"]).toBe("kept");
    const again = clone.withOptions({ timeout: 99 });
    expect(again.timeout).toBe(99);
    expect(again.apiKey).toBe("k2");
  });

  it("lets a clone replace the credential in either form", async () => {
    const options = { verifier: verifier(() => ({ tls: TEST_PIN })), transportMode: "tls" as const };
    const seams = { documentFetch: docs.fetch, tls: { ca: TEST_CERT } };
    const allowed = (client: unknown): boolean | undefined => (client as { _options: { dangerouslyAllowBrowser?: boolean } })._options.dangerouslyAllowBrowser;
    const withToken = await createEnclaveOpenAIClient(tls.host, "tinfoilsh/repo", options, { bearerToken: "jwt" }, seams);
    expect(withToken.apiKey).toBe("jwt");
    expect(allowed(withToken)).toBe(true);
    const keyed = withToken.withOptions({ apiKey: "k" });
    expect(keyed.apiKey).toBe("k");
    expect(allowed(keyed)).toBeUndefined();
    const withKey = await createEnclaveOpenAIClient(tls.host, "tinfoilsh/repo", options, { apiKey: "k" }, seams);
    const tokened = withKey.withOptions({ bearerToken: "jwt2" });
    expect(tokened.apiKey).toBe("jwt2");
    expect(allowed(tokened)).toBe(true);
    expect(tokened.withOptions({ bearerToken: "jwt3" }).apiKey).toBe("jwt3");
  });
});

describe("EnclaveHTTPClient over EHBP", () => {
  it("seals requests to the enclave's key and reaches the enclave through a proxy with the enclave header", async () => {
    const docs = documents();
    const proxied = await createEnclaveHTTPClient(
      "enclave.example",
      "",
      { verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex })), transportMode: "ehbp", baseURL: `${ehbp.origin}/` },
      { documentFetch: docs.fetch },
    );
    expect(proxied.baseURL()).toBe(`${ehbp.origin}/`);
    expect(proxied.enclave()).toBe("enclave.example");
    expect(proxied.repo()).toBe("");
    const res = await proxied.fetch(`${ehbp.origin}/echo`, { method: "POST", body: "prompt" });
    expect(await res.json()).toEqual({ path: "/echo", sealed: true, enclave: "https://enclave.example", text: "prompt" });
    const bodiless = await (await proxied.fetch(`${ehbp.origin}/echo`)).json();
    expect(bodiless.sealed).toBe(false);
    await expect(proxied.fetch("https://enclave.example/echo", { method: "POST", body: "x" })).rejects.toThrow();
    await expect(proxied.fetch("https://other.example/echo")).rejects.toThrow(/client is bound to enclave/);
  });

  it("replays once after the enclave rotates its key, re-verifying in between", async () => {
    const stale = await (await Identity.generate()).getPublicKeyHex();
    let verified = 0;
    const docs = documents();
    const client = await createEnclaveHTTPClient(
      "enclave.example",
      "",
      { verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: verified++ === 0 ? stale : ehbp.publicKeyHex })), transportMode: "ehbp", baseURL: `${ehbp.origin}/` },
      { documentFetch: docs.fetch, sleep: async () => {} },
    );
    expect(client.current()?.hpkePublicKey()).toBe(stale);
    const before = ehbp.seen.length;
    const res = await client.fetch(`${ehbp.origin}/echo`, { method: "POST", body: "again" });
    expect((await res.json()).text).toBe("again");
    expect(verified).toBe(2);
    expect(ehbp.seen.length).toBe(before + 1);
    expect(client.current()?.hpkePublicKey()).toBe(ehbp.publicKeyHex);
  });

  it("runs the caller's verification check and backs an OpenAI client on the proxy base URL", async () => {
    const seen: string[] = [];
    const docs = documents();
    const ai = await createEnclaveOpenAIClient(
      "enclave.example",
      "",
      {
        verifier: verifier(() => ({ tls: "ab".repeat(32), hpke: ehbp.publicKeyHex })),
        transportMode: "ehbp",
        baseURL: `${ehbp.origin}/`,
        verificationCheck: (v) => void seen.push(v.hpkePublicKey()!),
      },
      { apiKey: "k" },
      { documentFetch: docs.fetch },
    );
    expect(seen).toEqual([ehbp.publicKeyHex]);
    expect(ai.baseURL).toBe(`${ehbp.origin}/`);
    expect(ai.httpClient()).toBeInstanceOf(EnclaveHTTPClient);
    const completion = await ai.chat.completions.create({ model: "test", messages: [{ role: "user", content: "hi" }] });
    expect(completion.choices[0]!.message.content).toBe("sealed");
    const last = ehbp.seen[ehbp.seen.length - 1]!;
    expect(last.path).toBe("/chat/completions");
    expect(last.sealed).toBe(true);
    expect(last.headers["x-tinfoil-enclave-url"]).toBe("https://enclave.example");
    expect(last.headers.authorization).toBe("Bearer k");
  });
});
