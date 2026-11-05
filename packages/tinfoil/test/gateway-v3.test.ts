import { describe, expect, it, vi } from "vitest";
import { shapeGatewayRequest, rankHosts } from "../src/gateway-request.js";
import { prepareRequest } from "../src/request.js";
import { ConfigurationError } from "../src/errors.js";
function request(body: BodyInit, headers: HeadersInit = {}, path = "/v1/chat/completions") {
  return prepareRequest(path, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer test-api-key", ...headers }, body }, "https://gateway.test");
}
describe("normative gateway shaping", () => {
  it("uses independent HKDF domains and the Bearer credential, matching the protocol vector", async () => {
    const value = request('{"model":"test-model","messages":[{"role":"user","content":"hello"}]}');
    await shapeGatewayRequest(value, "test-secret");
    expect(JSON.parse(value.init.body as string).cache_salt).toBe("DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8");
    expect(new Headers(value.init.headers).get("x-tinfoil-cache-prefix")).toBe("ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6");
    expect(new Headers(value.init.headers).get("x-tinfoil-model")).toBe("test-model");
  });
  it("preserves int64 tokens, replaces salt and removes the secret before sealing", async () => {
    const value = request('{"model":"m","seed":9007199254740993,"cache_salt":"old","user_cache_secret":"body-secret","messages":[{"n":9007199254740993}]}');
    await shapeGatewayRequest(value, "client-secret");
    expect(value.init.body).toContain('"seed":9007199254740993');
    expect(value.init.body).toContain('"n":9007199254740993');
    expect(value.init.body).not.toContain("user_cache_secret");
    expect(value.init.body).not.toContain("old");
    expect([...new Headers(value.init.headers).values()].join(" ")).not.toContain("secret");
  });
  it("preserves explicit model, normalizes bearer, and prioritizes instructions", async () => {
    const a = request('{"model":"m","instructions":"system","input":"one"}', { "x-tinfoil-model": "override", authorization: "bEaReR   test-api-key  " });
    const b = request('{"model":"n","instructions":"system","input":"two"}');
    await shapeGatewayRequest(a, "test-secret"); await shapeGatewayRequest(b, "test-secret");
    expect(new Headers(a.init.headers).get("x-tinfoil-model")).toBe("override");
    expect(new Headers(a.init.headers).get("x-tinfoil-cache-prefix")).toBe(new Headers(b.init.headers).get("x-tinfoil-cache-prefix"));
    expect(JSON.parse(a.init.body as string).cache_salt).toBe(JSON.parse(b.init.body as string).cache_salt);
  });
  it("leaves malformed/nonobject bytes untouched and obeys prefix override rules", async () => {
    for (const raw of ['{"model":"m"} trailing', 'null', '[1,2]']) {
      const value = request(raw); await shapeGatewayRequest(value, "secret"); expect(value.init.body).toBe(raw); expect(new Headers(value.init.headers).has("x-tinfoil-model")).toBe(false);
    }
    const empty = request('{"model":"m","messages":[]}', { "x-tinfoil-cache-prefix": "caller" });
    await shapeGatewayRequest(empty, "secret"); expect(new Headers(empty.init.headers).has("x-tinfoil-cache-prefix")).toBe(false);
    const none = request('{"model":"m"}', { "x-tinfoil-cache-prefix": "caller" });
    await shapeGatewayRequest(none, ""); expect(new Headers(none.init.headers).get("x-tinfoil-cache-prefix")).toBe("caller");
  });
  it("leaves non-cache endpoint bodies unchanged", async () => {
    const value = request('{"model":"m","input":"hello"}', {}, "/v1/embeddings");
    await shapeGatewayRequest(value, "secret"); expect(value.init.body).toBe('{"model":"m","input":"hello"}');
  });
  it("buffers multipart exactly once and rejects repeated or file model fields", async () => {
    const valid = new FormData(); valid.append("model", "whisper"); valid.append("file", new Blob(["sound"]), "audio.wav");
    const value = prepareRequest("/audio/transcriptions", { method: "POST", body: valid }, "https://gateway.test");
    await shapeGatewayRequest(value, "secret"); expect(value.replayable).toBe(true); expect(new Headers(value.init.headers).get("x-tinfoil-model")).toBe("whisper");
    const missing = new FormData(); missing.append("file", new Blob(["sound"]), "audio.wav");
    const repeated = new FormData(); repeated.append("model", "a"); repeated.append("model", "b");
    const fileModel = new FormData(); fileModel.append("model", new Blob(["model"]), "model.txt");
    const empty = new FormData(); empty.append("model", "  ");
    for (const bad of [missing, repeated, fileModel, empty]) {
      await expect(shapeGatewayRequest(prepareRequest("/audio", { method: "POST", body: bad }, "https://gateway.test"), "")).rejects.toBeInstanceOf(ConfigurationError);
    }
  });
  it("discards the biased upper tail when shuffling hosts", async () => {
    const hosts = ["a.test", "b.test", "c.test"];
    const samples = [0xffffffff, 0xfffffffe, 0xffffffff];
    const random = vi.spyOn(crypto, "getRandomValues").mockImplementation(array => {
      expect(samples.length).toBeGreaterThan(0);
      (array as Uint32Array)[0] = samples.shift()!;
      return array;
    });
    try {
      // For three choices, reject 0xffffffff and accept 0xfffffffe (index 2).
      // For two choices, every uint32 is eligible, including 0xffffffff (index 1).
      expect(await rankHosts(hosts, "")).toEqual(hosts);
      expect(random).toHaveBeenCalledTimes(3);
      expect(hosts).toEqual(["a.test", "b.test", "c.test"]);
    } finally { random.mockRestore(); }
  });
  it("rendezvous rank is stable and moves remembered hosts first", async () => {
    const hosts = ["a.test", "b.test", "c.test"];
    const ranked = await rankHosts(hosts, "prefix"); expect(await rankHosts([...hosts].reverse(), "prefix")).toEqual(ranked);
    expect((await rankHosts(hosts, "prefix", "b.test"))[0]).toBe("b.test"); expect(hosts).toEqual(["a.test", "b.test", "c.test"]);
  });
});
