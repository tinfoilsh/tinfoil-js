import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { Identity } from "ehbp";
const mocks = vi.hoisted(() => ({ verify: vi.fn(), acquire: vi.fn() }));
vi.mock("../src/env.js", () => ({ isRealBrowser: () => true, isBun: () => false }));
vi.mock("@tinfoilsh/verifier", async original => ({ ...await original<object>(), Verifier: class { verify = mocks.verify; } }));
vi.mock("../src/acquisition.js", async original => ({ ...await original<object>(), fetchAttestationDocument: mocks.acquire }));
import { SecureClient } from "../src/secure-client.js";
import { AttestationError, ConfigurationError } from "../src/errors.js";
const options = { enclaveURL: "https://enclave.test", configRepo: "tinfoilsh/workload" };
beforeEach(() => { mocks.verify.mockReset(); mocks.acquire.mockReset().mockResolvedValue(new Uint8Array([1])); });
afterEach(() => vi.restoreAllMocks());
describe("browser channel capability", () => {
  it("rejects TLS construction and verified WebSockets before network work", async () => {
    expect(() => new SecureClient({ ...options, transport: "tls" })).toThrow(ConfigurationError);
    const client = new SecureClient(options);
    await expect(client.createWebSocket("/v1/realtime")).rejects.toThrow(ConfigurationError);
    expect(client.inspect()).toBeUndefined();
    expect(mocks.acquire).not.toHaveBeenCalled();
  });
  it("ready initializes HPKE with the verified key before publishing the binding", async () => {
    const key = await (await Identity.generate()).getPublicKeyHex();
    const verification = { freshnessExpiresAt: new Date(Date.now() + 60_000), hpkePublicKey: () => key, tlsPublicKeyFingerprint: () => "a".repeat(64) };
    mocks.verify.mockResolvedValue(verification);
    const initialize = vi.spyOn(Identity, "fromPublicKeyHex");
    const client = new SecureClient(options);
    await client.ready();
    expect(mocks.verify).toHaveBeenCalledTimes(1);
    expect(initialize).toHaveBeenCalledExactlyOnceWith(key);
    expect(client.inspect()?.verification).toBe(verification);
    expect(mocks.acquire.mock.calls[0][1]).toBe(mocks.verify.mock.calls[0][1]);
  });
  it("ready rejects a missing HPKE key without publishing a TLS-only binding", async () => {
    mocks.verify.mockResolvedValue({ freshnessExpiresAt: new Date(Date.now() + 60_000), hpkePublicKey: () => undefined, tlsPublicKeyFingerprint: () => "a".repeat(64) });
    const initialize = vi.spyOn(Identity, "fromPublicKeyHex");
    const client = new SecureClient(options);
    await expect(client.ready()).rejects.toBeInstanceOf(AttestationError);
    expect(initialize).not.toHaveBeenCalled();
    expect(client.inspect()).toBeUndefined();
  });
});
