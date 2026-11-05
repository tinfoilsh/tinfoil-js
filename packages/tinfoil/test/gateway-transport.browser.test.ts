import { CipherSuite, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from "hpke";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Identity, PROTOCOL, hexToBytes, HPKE_REQUEST_INFO } from "ehbp";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch.js";
import { shapeGatewayRequest } from "../src/gateway-request.js";
import { prepareRequest } from "../src/request.js";
import { AttestationError } from "../src/errors.js";
afterEach(() => vi.restoreAllMocks());
describe("portable gateway and EHBP", () => {
  it("matches gateway cache vectors with the runtime WebCrypto implementation", async () => {
    const request = prepareRequest("/chat/completions", { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer test-api-key" }, body: '{"model":"test-model","messages":[{"role":"user","content":"hello"}]}' }, "https://gateway.test");
    await shapeGatewayRequest(request, "test-secret");
    expect(JSON.parse(request.init.body as string).cache_salt).toBe("DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8");
    expect(new Headers(request.init.headers).get("x-tinfoil-cache-prefix")).toBe("ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6");
  });
  it("seals request plaintext to the supplied HPKE key and passes intermediary errors", async () => {
    const identity = await Identity.generate(); let recovered = "";
    vi.spyOn(globalThis, "fetch").mockImplementation(async input => {
      const request = input as Request;
      const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
      const receiver = await suite.SetupRecipient(identity.getPrivateKey(), hexToBytes(request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER)!), { info: new TextEncoder().encode(HPKE_REQUEST_INFO) });
      const wire = new Uint8Array(await request.arrayBuffer());
      expect(new DataView(wire.buffer).getUint32(0, false)).toBe(wire.length - 4);
      recovered = new TextDecoder().decode(await receiver.Open(wire.subarray(4)));
      return new Response("gateway unavailable", { status: 503 });
    });
    const transport = createEncryptedBodyFetch("https://gateway.test", await identity.getPublicKeyHex(), "https://enclave.test");
    const response = await transport.fetch("/chat/completions", { method: "POST", body: "highly private prompt" });
    expect(recovered).toBe("highly private prompt"); expect(response.status).toBe(503);
  });
  it("rejects a success without a response nonce and malformed response nonces", async () => {
    const identity = await Identity.generate();
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("untrusted success"));
    const transport = createEncryptedBodyFetch("https://gateway.test", await identity.getPublicKeyHex());
    await expect(transport.fetch("/chat/completions", { method: "POST", body: "private" })).rejects.toBeInstanceOf(AttestationError);
    fetch.mockResolvedValue(new Response("untrusted", { headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: "not-a-nonce" } }));
    await expect(transport.fetch("/chat/completions", { method: "POST", body: "private" })).rejects.toBeInstanceOf(AttestationError);
  });
});
