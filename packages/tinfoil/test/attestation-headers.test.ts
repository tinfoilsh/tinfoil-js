import { afterEach, describe, expect, it, vi } from "vitest";
import metadata from "../package.json";
import { fetchAttestationDocument, fetchRouters, acquireBytes, copyAcquisitionOptions } from "../src/acquisition.js";
import { NetworkError, ConfigurationError } from "../src/errors.js";
import { SDK_VERSION } from "../src/version.js";
afterEach(() => vi.restoreAllMocks());
describe("v3 document acquisition", () => {
  it("carries version, nonce and relay endpoint independently of untrusted bytes", async () => {
    const captured: Request[] = [];
    const fetch = vi.fn(async (input, init) => { captured.push(new Request(input, init)); return new Response("untrusted"); });
    const bytes = await fetchAttestationDocument("https://enclave.test", new Uint8Array(32).fill(15), { fetch, relayURL: "https://relay.test/v1", requestInit: { credentials: "include", headers: { "x-custom": "kept" } } });
    expect(new TextDecoder().decode(bytes)).toBe("untrusted"); expect(SDK_VERSION).toBe(metadata.version);
    expect(captured[0].url).toBe(`https://relay.test/.well-known/tinfoil-attestation?nonce=${"0f".repeat(32)}&enclave=enclave.test`);
    expect(captured[0].headers.get("Tinfoil-SDK-Version")).toBe(metadata.version); expect(new URL(captured[0].url).searchParams.get("enclave")).toBe("enclave.test"); expect(captured[0].credentials).toBe("include");
  });
  it("bounds replies and closes bodies on HTTP and size errors", async () => {
    const cancel = vi.fn(); const stream = () => new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(5)); }, cancel });
    await expect(acquireBytes(new URL("https://test"), { fetch: async () => new Response(stream()), maxResponseBytes: 4 })).rejects.toBeInstanceOf(NetworkError); expect(cancel).toHaveBeenCalled();
    cancel.mockClear(); await expect(acquireBytes(new URL("https://test"), { fetch: async () => new Response(stream(), { status: 503 }) })).rejects.toBeInstanceOf(NetworkError); expect(cancel).toHaveBeenCalled();
  });
  it("applies network deadline and preserves caller cancellation", async () => {
    const fetch: typeof globalThis.fetch = async (_input, init) => new Promise((_resolve, reject) => init!.signal!.addEventListener("abort", () => reject(init!.signal!.reason)));
    await expect(acquireBytes(new URL("https://test"), { fetch, timeoutMs: 5 })).rejects.toBeInstanceOf(NetworkError);
    const controller = new AbortController(), reason = new Error("caller"); const operation = acquireBytes(new URL("https://test"), { fetch }, controller.signal); controller.abort(reason); await expect(operation).rejects.toBe(reason);
  });
  it("validates limits/nonce before network and only returns untrusted router candidates", async () => {
    expect(() => copyAcquisitionOptions({ timeoutMs: 0 })).toThrow(ConfigurationError);
    await expect(fetchAttestationDocument("https://test", new Uint8Array(1))).rejects.toBeInstanceOf(ConfigurationError);
    const routers = await fetchRouters("https://discovery.test", { fetch: async () => Response.json(["a.test", "https://b.test"]) });
    expect(routers).toEqual(["https://a.test", "https://b.test"]);
    await expect(fetchRouters("https://discovery.test", { fetch: async () => Response.json(["http://a.test"]) })).rejects.toBeInstanceOf(NetworkError);
  });
  it("rejects acquisition redirects by default, permits configured HTTPS redirects and blocks downgrade", async () => {
    const sent: Request[] = [];
    const fetch = vi.fn(async (input, init) => {
      const request = new Request(input, init); sent.push(request);
      return request.url === "https://first.test/" ? new Response(null, { status: 302, headers: { location: "https://second.test/" } }) : new Response("document");
    });
    await expect(acquireBytes(new URL("https://first.test"), { fetch })).rejects.toBeInstanceOf(NetworkError);
    sent.length = 0;
    await acquireBytes(new URL("https://first.test"), { fetch, requestInit: { redirect: "follow", headers: { authorization: "secret" } } });
    expect(sent).toHaveLength(2); expect(sent[0].headers.get("authorization")).toBe("secret"); expect(sent[1].headers.has("authorization")).toBe(false);
    fetch.mockImplementation(async () => new Response(null, { status: 302, headers: { location: "http://plaintext.test/" } }));
    await expect(acquireBytes(new URL("https://first.test"), { fetch, requestInit: { redirect: "follow" } })).rejects.toThrow("HTTPS");
  });

});
