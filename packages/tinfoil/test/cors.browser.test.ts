import { describe, expect, it } from "vitest";
import { Identity } from "ehbp";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch.js";
// @ts-expect-error The test server supplies the local relay origin.
import relay from "virtual:tinfoil-browser-relay";
async function transport() { const identity = await Identity.generate(); return createEncryptedBodyFetch(relay, await identity.getPublicKeyHex(), "https://verified-enclave.test"); }
const request = () => ({ method: "POST", headers: { "content-type": "application/json", "X-Tinfoil-Model": "model", "X-Tinfoil-Seal": "verified-enclave.test", authorization: "Bearer synthetic" }, body: "secret browser prompt" });
describe("actual browser CORS on an EHBP forwarding relay", () => {
  it("preflights routing headers, preserves the exact relay and exposes seal negotiation", async () => {
    const response = await (await transport()).fetch("/allowed", request());
    expect(response.status).toBe(412); expect(response.headers.get("x-tinfoil-seal")).toBe("next-enclave.test");
    const seen = await response.json(); expect(seen).toMatchObject({ model: "model", seal: "verified-enclave.test", enclave: "https://verified-enclave.test", private: true }); expect(seen.size).toBeGreaterThan(32);
  });
  it("cannot read an unexposed seal header", async () => {
    const response = await (await transport()).fetch("/unexposed", request());
    expect(response.status).toBe(412); expect(response.headers.get("x-tinfoil-seal")).toBeNull();
  });
  it("fails before application traffic when the relay does not permit CORS", async () => {
    await expect((await transport()).fetch("/blocked", request())).rejects.toBeInstanceOf(TypeError);
  });
});
