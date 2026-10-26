import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { KeyConfigMismatchError } from "ehbp";
const mocks = vi.hoisted(() => ({ verify: vi.fn(), fetchEvidence: vi.fn(), build: vi.fn(), nonce: 0 }));
vi.mock("@tinfoilsh/verifier", () => ({
  UsageError: class UsageError extends Error {}, VerificationError: class VerificationError extends Error {},
  Verifier: class { verify = mocks.verify; },
  parseReference: (value: string) => { if (!value.includes("/")) throw new Error("bad reference"); },
  randomNonce: () => new Uint8Array(32).fill(++mocks.nonce),
}));
vi.mock("../src/acquisition.js", async original => ({ ...await original<object>(), fetchAttestationDocument: mocks.fetchEvidence }));
vi.mock("../src/secure-fetch.js", () => ({ createSecureFetch: mocks.build }));
import { SecureClient } from "../src/secure-client.js";
import { AttestationError, NetworkError, ConfigurationError } from "../src/errors.js";
import { Client } from "../src/client.js";
const options = { enclaveURL: "https://enclave.test", configRepo: "tinfoilsh/workload" };
const success = (expiry = Date.now() + 60_000, key = "key") => Object.freeze({ freshnessExpiresAt: new Date(expiry), tlsPublicKeyFingerprint: () => "a".repeat(64), hpkePublicKey: () => key });
function deferred<T>() { let resolve!: (value: T) => void, reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
beforeEach(() => { mocks.verify.mockReset().mockResolvedValue(success()); mocks.fetchEvidence.mockReset().mockResolvedValue(new Uint8Array([1])); mocks.build.mockReset().mockResolvedValue({ fetch: vi.fn(async () => new Response("ok")), getSessionRecoveryToken: vi.fn() }); mocks.nonce = 0; });
afterEach(() => vi.useRealTimers());
describe("SecureClient v3 ownership", () => {
  it("requires a fixed endpoint, rejects plaintext TLS/proxy TLS and keeps inspection passive", () => {
    expect(() => new SecureClient(undefined as never)).toThrow(ConfigurationError);
    expect(() => new SecureClient({ ...options, transport: "tls", baseURL: "http://proxy.test" })).toThrow(ConfigurationError);
    const client = new SecureClient(options); expect(client.inspect()).toBeUndefined(); expect(mocks.fetchEvidence).not.toHaveBeenCalled();
  });
  it("shares initialization and gives acquisition and verifier the same fresh nonce", async () => {
    const client = new SecureClient(options);
    await Promise.all([client.ready(), client.ready(), client.ready()]);
    expect(mocks.verify).toHaveBeenCalledTimes(1);
    expect(mocks.fetchEvidence.mock.calls[0][1]).toBe(mocks.verify.mock.calls[0][1]);
    expect(mocks.verify.mock.calls[0][2]).toBe(options.configRepo);
    expect(client.inspect()?.endpoint).toBe(options.enclaveURL);
  });
  it("cancels one waiter without cancelling shared work", async () => {
    const gate = deferred<ReturnType<typeof success>>(); mocks.verify.mockReturnValue(gate.promise);
    const client = new SecureClient(options); const controller = new AbortController();
    const cancelled = client.ready({ signal: controller.signal }); const continuing = client.ready();
    controller.abort(new Error("caller cancellation")); await expect(cancelled).rejects.toThrow("caller cancellation");
    gate.resolve(success()); await continuing; expect(mocks.verify).toHaveBeenCalledTimes(1);
  });
  it("shares terminal failure, clears failed work, preserves valid prior evidence", async () => {
    const client = new SecureClient(options); await client.ready(); const original = client.inspect();
    mocks.fetchEvidence.mockRejectedValue(new NetworkError("down"));
    const a = client.refresh(), b = client.refresh();
    await expect(a).rejects.toThrow("down"); await expect(b).rejects.toThrow("down");
    expect(mocks.fetchEvidence).toHaveBeenCalledTimes(3); expect(client.inspect()).toEqual(original);
    await client.fetch("/ok");
    mocks.fetchEvidence.mockResolvedValue(new Uint8Array([2])); await client.refresh(); expect(mocks.verify).toHaveBeenCalledTimes(2);
  });
  it("refreshes at strict expiry and does not authorize unbounded embedded results", async () => {
    vi.useFakeTimers(); vi.setSystemTime(1000);
    mocks.verify.mockResolvedValueOnce(success(2000)).mockResolvedValue(success(5000));
    const client = new SecureClient(options); await client.ready(); vi.setSystemTime(2000); await client.fetch("/ok"); expect(mocks.verify).toHaveBeenCalledTimes(2);
    mocks.verify.mockResolvedValue({ ...success(), freshnessExpiresAt: undefined }); await expect(client.refresh()).rejects.toThrow("freshness deadline");
  });
  it("does not publish when construction outlives freshness", async () => {
    vi.useFakeTimers(); vi.setSystemTime(1000); mocks.verify.mockImplementation(() => success(2000));
    mocks.build.mockImplementation(async () => { vi.setSystemTime(2000); return { fetch: vi.fn() }; });
    const client = new SecureClient(options); await expect(client.ready()).rejects.toThrow(AttestationError); expect(client.inspect()).toBeUndefined();
  });
  it("invalidates only the captured rejected binding and never replays standalone requests", async () => {
    const delayed = deferred<Response>(); const oldFetch = vi.fn(() => delayed.promise); const nextFetch = vi.fn(async () => new Response("new"));
    mocks.build.mockResolvedValueOnce({ fetch: oldFetch }).mockResolvedValue({ fetch: nextFetch });
    const client = new SecureClient(options); const pending = client.fetch("/old"); await vi.waitFor(() => expect(oldFetch).toHaveBeenCalled());
    await client.refresh(); delayed.reject(new KeyConfigMismatchError()); await expect(pending).rejects.toBeInstanceOf(AttestationError);
    expect(await (await client.fetch("/next")).text()).toBe("new"); expect(mocks.verify).toHaveBeenCalledTimes(2); expect(oldFetch).toHaveBeenCalledTimes(1);
  });
  it("allows an admitted stream to finish after expiry and refresh", async () => {
    vi.useFakeTimers(); vi.setSystemTime(1000); let stream!: ReadableStreamDefaultController;
    mocks.verify.mockResolvedValueOnce(success(2000)).mockResolvedValue(success(5000));
    mocks.build.mockResolvedValueOnce({ fetch: async () => new Response(new ReadableStream({ start(controller) { stream = controller; } })) }).mockResolvedValue({ fetch: async () => new Response("new") });
    const client = new SecureClient(options); const response = await client.fetch("/stream"); vi.setSystemTime(2000); await client.ready();
    expect(mocks.verify).toHaveBeenCalledTimes(2);
    expect(mocks.build).toHaveBeenCalledTimes(2);
    expect(client.inspect()?.verification.freshnessExpiresAt?.getTime()).toBe(5000);
    stream.enqueue(new TextEncoder().encode("complete")); stream.close(); expect(await response.text()).toBe("complete");
  });
  it("preserves internal failures and rejects wrong origins before setup", async () => {
    const bug = new Error("internal initialization defect"); mocks.verify.mockRejectedValue(bug);
    const client = new SecureClient(options); await expect(client.ready()).rejects.toBe(bug); expect(mocks.verify).toHaveBeenCalledTimes(1);
    mocks.verify.mockClear(); await expect(client.fetch("https://other.test", { headers: { authorization: "secret" } })).rejects.toBeInstanceOf(ConfigurationError); expect(mocks.verify).not.toHaveBeenCalled();
  });
  it("SDK owns one rotation replay and reuses the already shaped body", async () => {
    const old = vi.fn(async () => { throw new KeyConfigMismatchError(); }); const fresh = vi.fn(async () => new Response("ok"));
    mocks.build.mockResolvedValueOnce({ fetch: old }).mockResolvedValue({ fetch: fresh });
    const client = new Client({ ...options, userCacheSecret: "private" });
    await client.fetch("/v1/chat/completions", { method: "POST", body: '{"model":"m","seed":9007199254740993}' });
    expect(old.mock.calls[0][1].body).toBe(fresh.mock.calls[0][1].body); expect(fresh.mock.calls[0][1].body).toContain("9007199254740993"); expect(fresh.mock.calls[0][1].body).toContain("user_cache_secret");
  });
  it("honors an explicit null signal override on a Request input", async () => {
    const controller = new AbortController(); controller.abort(new Error("old signal"));
    const request = new Request("https://enclave.test/path", { signal: controller.signal });
    const client = new SecureClient(options);
    await expect(client.fetch(request, { signal: null })).resolves.toBeInstanceOf(Response);
  });

});
