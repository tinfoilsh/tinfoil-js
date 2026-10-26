import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { KeyConfigMismatchError } from "ehbp";
const mocks = vi.hoisted(() => ({ evidence: vi.fn(), verify: vi.fn(), send: vi.fn(), policies: [] as unknown[] }));
vi.mock("@tinfoilsh/verifier", () => ({
  UsageError: class UsageError extends Error {}, VerificationError: class VerificationError extends Error {},
  Verifier: class { constructor(options: unknown) { mocks.policies.push(options); } verify = mocks.verify; },
  parseReference: () => ({}), randomNonce: () => crypto.getRandomValues(new Uint8Array(32)),
}));
vi.mock("../src/acquisition.js", async original => ({ ...await original<object>(), fetchAttestationDocument: mocks.evidence }));
vi.mock("../src/secure-fetch.js", () => ({ createSecureFetch: async (_base: string, key: string) => ({ fetch: (url: unknown, init: unknown) => mocks.send(key, url, init) }) }));
import { Gateway } from "../src/gateway.js";
import { ConfigurationError, AttestationError, NetworkError } from "../src/errors.js";
const raw = '{"model":"m","messages":[{"role":"user","content":"hello"}],"seed":9007199254740993}';
const init = () => ({ method: "POST", body: raw, headers: { "content-type": "application/json", authorization: "Bearer credential" } });
const catalog = () => ({ m: { repo: "tinfoilsh/model", hosts: ["a.test"] } });
beforeEach(() => {
  mocks.evidence.mockReset().mockImplementation(async endpoint => new TextEncoder().encode(endpoint));
  mocks.verify.mockReset().mockImplementation(async bytes => ({ freshnessExpiresAt: new Date(Date.now() + 60_000), hpkePublicKey: () => new TextDecoder().decode(bytes), tlsPublicKeyFingerprint: () => undefined }));
  mocks.send.mockReset().mockResolvedValue(new Response("ok")); mocks.policies.length = 0;
});
afterEach(() => vi.useRealTimers());
describe("gateway v3 public routing", () => {
  it("re-seals identical shaped bytes at the same gateway, verifies the target and remembers affinity", async () => {
    mocks.send.mockImplementation(async key => key === "https://a.test" ? new Response("reroute", { status: 412, headers: { "x-tinfoil-seal": "b.test" } }) : new Response("ok"));
    const gateway = new Gateway("https://gateway.test/v1/", { catalog, userCacheSecret: "secret" });
    await gateway.fetch("/chat/completions", init());
    expect(mocks.evidence.mock.calls.map(call => call[0])).toEqual(["https://a.test", "https://b.test"]);
    expect(mocks.evidence.mock.calls.every(call => call[2].relayURL === "https://gateway.test")).toBe(true);
    expect(mocks.send.mock.calls[0][2].body).toBe(mocks.send.mock.calls[1][2].body);
    expect(mocks.send.mock.calls.every(call => new URL(call[1]).origin === "https://gateway.test")).toBe(true);
    await gateway.fetch("/chat/completions", init());
    expect(mocks.send.mock.calls[2][0]).toBe("https://b.test"); expect(mocks.verify).toHaveBeenCalledTimes(2);
  });
  it("shares target verification across concurrent requests", async () => {
    const gateway = new Gateway("https://gateway.test", { catalog, userCacheSecret: "secret" });
    await Promise.all([gateway.fetch("/chat/completions", init()), gateway.fetch("/chat/completions", init())]);
    expect(mocks.verify).toHaveBeenCalledTimes(1);
  });
  it("rejects catalog pin mismatch before a cached handle is touched", async () => {
    let offered = "tinfoilsh/model";
    const gateway = new Gateway("https://gateway.test", { catalog: () => ({ m: { repo: offered, hosts: ["a.test"] } }), pins: { m: "tinfoilsh/model@v1" }, userCacheSecret: "secret" });
    await gateway.fetch("/chat/completions", init()); offered = "tinfoilsh/other";
    await expect(gateway.fetch("/chat/completions", init())).rejects.toBeInstanceOf(AttestationError);
    expect(mocks.evidence).toHaveBeenCalledTimes(1); expect(mocks.send).toHaveBeenCalledTimes(1);
  });
  it("copies model options, replaces defaults and scopes cache to pinned model", async () => {
    const defaults = { freshnessMaxAgeMs: 12345 };
    const pins = { m: { reference: "tinfoilsh/model", verification: {} }, n: { reference: "tinfoilsh/model", verification: { freshnessMaxAgeMs: 54321 } } };
    const gateway = new Gateway("https://gateway.test", { catalog: () => ({ ...catalog(), n: catalog().m }), pins, verification: defaults, userCacheSecret: "secret" });
    pins.m.reference = "tinfoilsh/attacker"; pins.n.verification.freshnessMaxAgeMs = 1; defaults.freshnessMaxAgeMs = 2;
    await gateway.fetch("/chat/completions", init()); await gateway.fetch("/chat/completions", { ...init(), body: raw.replace('"m"', '"n"') });
    expect(mocks.verify.mock.calls.map(call => call[2])).toEqual(["tinfoilsh/model", "tinfoilsh/model"]);
    expect(mocks.policies.slice(-2)).toEqual([{}, { freshnessMaxAgeMs: 54321 }]); expect(gateway.replicas()).toHaveLength(2);
  });
  it("retains the pinned replica policy through expiry followed by key-rotation recovery", async () => {
    vi.useFakeTimers(); vi.setSystemTime(1000); let generation = 0;
    mocks.verify.mockImplementation(async () => ({ freshnessExpiresAt: new Date(Date.now() + 1000), hpkePublicKey: () => `key-${++generation}`, tlsPublicKeyFingerprint: () => undefined }));
    mocks.send.mockImplementation(async key => { if (key === "key-2") throw new KeyConfigMismatchError(); return new Response(key); });
    const pin = { reference: "tinfoilsh/model@v1", verification: { freshnessMaxAgeMs: 3000 } };
    const gateway = new Gateway("https://gateway.test", { catalog, pins: { m: pin }, userCacheSecret: "secret" });
    expect(await (await gateway.fetch("/chat/completions", init())).text()).toBe("key-1");
    const createdPolicies = mocks.policies.length; pin.reference = "tinfoilsh/changed"; pin.verification.freshnessMaxAgeMs = 1;
    vi.setSystemTime(2000);
    expect(await (await gateway.fetch("/chat/completions", init())).text()).toBe("key-3");
    expect(mocks.verify.mock.calls.map(call => call[2])).toEqual(Array(3).fill("tinfoilsh/model@v1"));
    expect(mocks.evidence.mock.calls.map(call => call[0])).toEqual(Array(3).fill("https://a.test"));
    expect(mocks.policies).toHaveLength(createdPolicies); expect(mocks.policies.at(-1)).toEqual({ freshnessMaxAgeMs: 3000 });
    expect(gateway.replicas()).toHaveLength(1);
    expect(mocks.send.mock.calls.map(call => call[2].body).every(body => body === mocks.send.mock.calls[0][2].body)).toBe(true);
  });
  it("has a three-reseal budget and passes bare/same-host/other-status responses", async () => {
    let i = 0; mocks.send.mockImplementation(async () => new Response("again", { status: 412, headers: { "x-tinfoil-seal": `${++i}.test` } }));
    const gateway = new Gateway("https://gateway.test", { catalog, userCacheSecret: "secret" });
    await expect(gateway.fetch("/chat/completions", init())).rejects.toBeInstanceOf(NetworkError); expect(mocks.send).toHaveBeenCalledTimes(4);
    for (const [status, seal] of [[412, undefined], [412, "a.test"], [422, "b.test"]] as const) {
      mocks.send.mockReset().mockResolvedValue(new Response("pass", { status, headers: seal ? { "x-tinfoil-seal": seal } : undefined }));
      const direct = new Gateway("https://gateway.test", { catalog, userCacheSecret: "secret" });
      expect((await direct.fetch("/chat/completions", init())).status).toBe(status); expect(mocks.send).toHaveBeenCalledTimes(1);
    }
  });
  it("does not follow seal redirects for nonreplayable streams", async () => {
    mocks.send.mockResolvedValue(new Response("route", { status: 412, headers: { "x-tinfoil-seal": "b.test" } }));
    const gateway = new Gateway("https://gateway.test", { catalog, userCacheSecret: "secret" });
    const response = await gateway.fetch("/upload", { method: "POST", body: new ReadableStream(), headers: { "x-tinfoil-model": "m" }, duplex: "half" } as RequestInit);
    expect(response.status).toBe(412); expect(mocks.evidence).toHaveBeenCalledTimes(1);
  });
  it("rejects oversized multipart before catalog or replica contact and cancels its input", async () => {
    const source = vi.fn(catalog), cancelled = vi.fn();
    const chunk = new Uint8Array(8 * 1024 * 1024);
    const body = new ReadableStream({ pull(controller) { controller.enqueue(chunk); }, cancel: cancelled });
    const gateway = new Gateway("https://gateway.test", { catalog: source, userCacheSecret: "secret" });
    await expect(gateway.fetch("/audio/transcriptions", { method: "POST", headers: { "content-type": "multipart/form-data; boundary=synthetic" }, body, duplex: "half" } as RequestInit)).rejects.toThrow("exceeds 64 MiB");
    expect(source).not.toHaveBeenCalled(); expect(mocks.evidence).not.toHaveBeenCalled(); expect(mocks.send).not.toHaveBeenCalled(); expect(cancelled).toHaveBeenCalledTimes(1);
  });
  it("refuses unpinned models and keeps eligibility and inspection passive", async () => {
    const gateway = new Gateway("https://gateway.test", { catalog, pinnedOnly: true, pins: { n: "tinfoilsh/model" }, userCacheSecret: "secret" });
    expect(gateway.inspect()).toBeUndefined(); expect(gateway.serves("m")).toBe(false); expect(mocks.evidence).not.toHaveBeenCalled();
    await expect(gateway.fetch("/chat/completions", init())).rejects.toBeInstanceOf(ConfigurationError); expect(mocks.evidence).not.toHaveBeenCalled();
  });
  it("rejects model-reference/authorizer conflicts before catalog I/O", () => {
    const source = vi.fn(catalog);
    expect(() => new Gateway("https://gateway.test", { catalog: source, verification: { configAuthorizer: () => {} } })).toThrow(ConfigurationError);
    expect(() => new Gateway("https://gateway.test", { catalog: source, pins: { m: { reference: "tinfoilsh/model", verification: { configAuthorizer: () => {} } } } })).toThrow(ConfigurationError);
    expect(source).not.toHaveBeenCalled();
  });

  it("drops invalid fetched catalog entries and refuses invalid caller-supplied entries", async () => {
    const entries = { ...catalog(), tagged: { repo: "tinfoilsh/model@tag", hosts: ["a.test"] }, foreign: { repo: "other/model", hosts: ["a.test"] }, empty: { repo: "tinfoilsh/model", hosts: [] } };
    const gateway = new Gateway("https://gateway.test", { acquisition: { fetch: async () => Response.json(entries) }, userCacheSecret: "secret" });
    await gateway.ready("m");
    expect(gateway.serves("m")).toBe(true);
    for (const model of ["tagged", "foreign", "empty"]) expect(gateway.serves(model)).toBe(false);
    mocks.evidence.mockClear();
    const custom = new Gateway("https://gateway.test", { catalog: () => entries, userCacheSecret: "secret" });
    await expect(custom.ready("tagged")).rejects.toBeInstanceOf(ConfigurationError);
    expect(mocks.evidence).not.toHaveBeenCalled();
  });
  it("uses one catalog snapshot through resealing and disposes the redirect response", async () => {
    const source = vi.fn(catalog), discarded = vi.fn();
    mocks.send.mockImplementation(async key => key === "https://a.test"
      ? new Response(new ReadableStream({ cancel: discarded }), { status: 412, headers: { "x-tinfoil-seal": "b.test" } })
      : new Response("accepted"));
    const gateway = new Gateway("https://gateway.test", { catalog: source, userCacheSecret: "secret" });
    expect(await (await gateway.fetch("/chat/completions", init())).text()).toBe("accepted");
    expect(source).toHaveBeenCalledTimes(1); expect(discarded).toHaveBeenCalledTimes(1);
    expect(mocks.verify.mock.calls.every(call => call[2] === "tinfoilsh/model")).toBe(true);
  });

});
