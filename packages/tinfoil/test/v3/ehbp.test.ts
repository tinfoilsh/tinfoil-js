/**
 * The EHBP transport against a local EHBP server: sealed bodies round-trip,
 * a bodyless request passes through unsealed, a streamed response is
 * opened chunk by chunk as it arrives, a peer that no longer holds the key
 * is reported as such and the request is replayed after re-verification,
 * tunnels and reserved headers are refused, the proxy header travels in
 * plaintext, and the base URL rules.
 */
import { Identity } from "ehbp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, NetworkError } from "../../src/v3/errors.js";
import { Enclave } from "../../src/v3/internal/enclave.js";
import { isLoopback, validateBaseURL, validateTLSBaseURL } from "../../src/v3/internal/transport/base-url.js";
import { checkEHBP, ehbpMode } from "../../src/v3/internal/transport/ehbp.js";
import { ENCLAVE_URL_HEADER, withEnclaveURL } from "../../src/v3/internal/transport/header.js";
import { withReplay } from "../../src/v3/internal/transport/replay.js";
import { isKeyRejection, KeyedTransport, KeyRejectionError, PeerLacksKeyError, shapeOf } from "../../src/v3/internal/transport/transport.js";
import { KEY_X25519_HPKE_V1_FORMAT, type Verification, type Verifier } from "../../../verifier/src/v3/index.js";
import { paced, startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";

let server: EhbpServer;
let sseEnded = false;

function verification(hpke: string | undefined): Verification {
  return {
    cryptoMaterial: () => (hpke === undefined ? [] : [{ id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke }]),
    tlsPublicKeyFP: () => "ab".repeat(32),
    hpkePublicKey: () => hpke,
    freshnessExpiresAt: () => new Date(Date.now() + 60_000),
  } as unknown as Verification;
}

beforeAll(async () => {
  server = await startEhbpServer((seen) => {
    switch (seen.path) {
      case "/echo":
        return {
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ length: seen.body.length, text: new TextDecoder().decode(seen.body), enclave: seen.headers[ENCLAVE_URL_HEADER.toLowerCase()] ?? null, sealed: seen.sealed }),
        };
      case "/sse": {
        sseEnded = false;
        const chunks = paced(["data: chunk 1\n\n", "data: chunk 2\n\n", "data: chunk 3\n\n"], 60);
        const body = (async function* () {
          for await (const c of chunks) yield c;
          sseEnded = true;
        })();
        return { headers: { "content-type": "text/event-stream" }, body };
      }
      case "/plain":
        return { headers: { "content-type": "text/plain" }, body: "hello" };
      case "/nonce-less":
        return { plaintext: true, body: "unsealed" };
      case "/error":
        return { plaintext: true, status: 503, body: "busy" };
      default:
        return { status: 404, plaintext: true, body: "" };
    }
  });
});

afterAll(async () => {
  await server.close();
});

describe("checkEHBP", () => {
  it("refuses a CONNECT or an upgrade, and allows other requests with or without a body", () => {
    expect(() => checkEHBP(shapeOf("https://x.example/", { method: "CONNECT" }))).toThrow(ConfigurationError);
    expect(() => checkEHBP(shapeOf("https://x.example/", { headers: { Upgrade: "websocket" } }))).toThrow(/can't protect a protocol upgrade/);
    expect(() => checkEHBP(shapeOf("https://x.example/", { method: "POST", body: "x" }))).not.toThrow();
    expect(() => checkEHBP(shapeOf("http://x.example/"))).not.toThrow();
  });
});

describe("ehbpMode", () => {
  const mode = ehbpMode();

  it("binds to the attested HPKE key and rejects its absence or a malformed one", async () => {
    await expect(mode.bind(verification(undefined))).rejects.toThrow(/document endorses no HPKE key; cannot use the EHBP transport mode/);
    await expect(mode.bind(verification("zz"))).rejects.toBeInstanceOf(AttestationError);
    await expect(mode.bind(verification("ab".repeat(16)))).rejects.toThrow(/failed to parse HPKE public key/);
    expect(mode.name).toBe("ehbp");
  });

  it("seals a request body and opens the sealed response", async () => {
    const bound = await mode.bind(verification(server.publicKeyHex));
    const res = await bound.fetch(`${server.origin}/echo`, { method: "POST", body: "secret prompt", headers: { "content-type": "text/plain" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(res.headers.has("content-length")).toBe(false);
    expect(await res.json()).toEqual({ length: 13, text: "secret prompt", enclave: null, sealed: true });
    const last = server.seen[server.seen.length - 1]!;
    expect(last.sealed).toBe(true);
    expect(last.headers["ehbp-encapsulated-key"]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("passes a bodyless request through unsealed, with a plaintext response", async () => {
    const bound = await mode.bind(verification(server.publicKeyHex));
    const res = await bound.fetch(`${server.origin}/plain`);
    expect(await res.text()).toBe("hello");
    const last = server.seen[server.seen.length - 1]!;
    expect(last.sealed).toBe(false);
    expect(last.headers["ehbp-encapsulated-key"]).toBeUndefined();
  });

  it("opens a streamed response chunk by chunk as it arrives", async () => {
    const bound = await mode.bind(verification(server.publicKeyHex));
    const res = await bound.fetch(`${server.origin}/sse`, { method: "POST", body: "start" });
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    const first = await reader.read();
    expect(decoder.decode(first.value)).toBe("data: chunk 1\n\n");
    expect(sseEnded).toBe(false);
    let text = decoder.decode(first.value);
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value);
    }
    expect(text).toBe("data: chunk 1\n\ndata: chunk 2\n\ndata: chunk 3\n\n");
    expect(sseEnded).toBe(true);
  });

  it("seals a streaming request body frame by frame, sending it in full before the response", async () => {
    const bound = await mode.bind(verification(server.publicKeyHex));
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulled === 3) {
          controller.close();
          return;
        }
        pulled++;
        controller.enqueue(new Uint8Array(70 * 1024).fill(pulled));
      },
    });
    const res = await bound.fetch(`${server.origin}/echo`, { method: "POST", body, headers: { "content-type": "application/octet-stream" } });
    expect((await res.json()).length).toBe(3 * 70 * 1024);
    expect(pulled).toBe(3);
  });

  it("reports a peer that no longer holds the key, and the transport replays after re-verification", async () => {
    const other = await (await Identity.generate()).getPublicKeyHex();
    const stale = await mode.bind(verification(other));
    const before = server.seen.length;
    const err = await stale.fetch(`${server.origin}/echo`, { method: "POST", body: "x" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PeerLacksKeyError);
    expect((err as Error).message).toBe("attestation error: key configuration mismatch");
    expect(server.seen.length).toBe(before);

    let verified = 0;
    const verifier = { checkRepoVerifiability: () => {}, verifyV3At: async () => verification(verified++ === 0 ? other : server.publicKeyHex) } as unknown as Verifier;
    const enclave = await Enclave.create({ host: "127.0.0.1", repo: "", verifier, fetch: async () => new Response(new Uint8Array([1])), sleep: async () => {} });
    const transport = new KeyedTransport(enclave, mode);
    const rejected = await transport.fetch(`${server.origin}/echo`, { method: "POST", body: "y" }).catch((e: unknown) => e);
    expect(rejected).toBeInstanceOf(KeyRejectionError);
    const replayed = withReplay(transport.fetch, isKeyRejection);
    expect((await (await replayed(`${server.origin}/echo`, { method: "POST", body: "y" })).json()).text).toBe("y");
    expect(verified).toBe(2);
    expect(server.seen.length).toBe(before + 1);
  });

  it("returns a plaintext error status as is and rejects a sealed exchange answered without a nonce", async () => {
    const bound = await mode.bind(verification(server.publicKeyHex));
    const res = await bound.fetch(`${server.origin}/error`, { method: "POST", body: "x" });
    expect(res.status).toBe(503);
    expect(await res.text()).toBe("busy");
    await expect(bound.fetch(`${server.origin}/nonce-less`, { method: "POST", body: "x" })).rejects.toThrow(/answered without the Ehbp-Response-Nonce header/);
    await expect(bound.fetch(`${server.origin}/nonce-less`, { method: "POST", body: "x" })).rejects.toBeInstanceOf(NetworkError);
  });

  it("refuses tunnels, bodies on GET, and reserved headers before sending", async () => {
    const bound = await mode.bind(verification(server.publicKeyHex));
    const before = server.seen.length;
    await expect(bound.fetch(`${server.origin}/echo`, { method: "CONNECT" })).rejects.toThrow(ConfigurationError);
    await expect(bound.fetch(`${server.origin}/echo`, { headers: { upgrade: "websocket" } })).rejects.toThrow(ConfigurationError);
    await expect(bound.fetch(`${server.origin}/echo`, { method: "GET", body: "x" })).rejects.toThrow(/request with GET method cannot have a body/);
    await expect(bound.fetch(`${server.origin}/echo`, { method: "POST", body: "x", headers: { "Ehbp-Encapsulated-Key": "00" } })).rejects.toThrow(/reserved request header/);
    expect(server.seen.length).toBe(before);
  });

  it("carries the enclave header in plaintext when a proxy is in front, and omits it otherwise", async () => {
    const bound = await mode.bind(verification(server.publicKeyHex));
    const proxied = withEnclaveURL(bound.fetch, "enclave.example", server.origin);
    expect((await (await proxied(`${server.origin}/echo`, { method: "POST", body: "p" })).json()).enclave).toBe("https://enclave.example");
    const direct = withEnclaveURL(bound.fetch, "enclave.example", "");
    expect((await (await direct(`${server.origin}/echo`, { method: "POST", body: "d" })).json()).enclave).toBeNull();
  });

  it("sends through the fetch it is given", async () => {
    const urls: string[] = [];
    const observed = ehbpMode({
      fetch: async (input, init) => {
        urls.push(input instanceof Request ? input.url : String(input));
        return fetch(input, init);
      },
    });
    const bound = await observed.bind(verification(server.publicKeyHex));
    await (await bound.fetch(`${server.origin}/echo`, { method: "POST", body: "via" })).json();
    expect(urls).toEqual([`${server.origin}/echo`]);
  });
});

describe("base URL rules", () => {
  it("accepts HTTPS anywhere and HTTP only to a loopback host", () => {
    for (const ok of ["https://proxy.example/v1/", "http://localhost:8080/", "http://127.0.0.1/", "http://127.9.9.9:3000/x", "http://[::1]:8443/"]) {
      expect(() => validateBaseURL(ok), ok).not.toThrow();
    }
    for (const bad of ["http://proxy.example/", "http://10.0.0.1/", "ftp://x/", "/relative", "http://localhost.evil.example/"]) {
      expect(() => validateBaseURL(bad), bad).toThrow(ConfigurationError);
    }
    expect(isLoopback("LOCALHOST")).toBe(true);
    expect(isLoopback("[::1]")).toBe(true);
    expect(isLoopback("127.0.0.1")).toBe(true);
    expect(isLoopback("128.0.0.1")).toBe(false);
    expect(isLoopback("localhost.evil.example")).toBe(false);
  });

  it("requires a TLS-mode base URL to stay on the enclave's origin", () => {
    expect(() => validateTLSBaseURL("", "enclave.example")).not.toThrow();
    expect(() => validateTLSBaseURL("https://enclave.example:443/v1/", "enclave.example")).not.toThrow();
    expect(() => validateTLSBaseURL("https://proxy.example/v1/", "enclave.example")).toThrow(/is a proxy, which requires the EHBP transport mode/);
    expect(() => validateTLSBaseURL("not a url", "enclave.example")).toThrow(ConfigurationError);
  });
});
