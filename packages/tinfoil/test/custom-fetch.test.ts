import { describe, it, expect, vi, afterEach } from "vitest";
import assert from "node:assert";
import { Identity, PROTOCOL, bytesToHex, deriveResponseKeys, encryptChunk, hexToBytes,
  EXPORT_LABEL, EXPORT_LENGTH, HPKE_REQUEST_INFO, RESPONSE_NONCE_LENGTH } from "ehbp";
import { CipherSuite, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from "hpke";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import { createSecureFetch } from "../src/secure-fetch";

function encodeSingleChunk(payload: Uint8Array): Uint8Array {
  const chunkLength = new Uint8Array(4);
  new DataView(chunkLength.buffer).setUint32(0, payload.byteLength, false);

  const body = new Uint8Array(4 + payload.byteLength);
  body.set(chunkLength, 0);
  body.set(payload, 4);
  return body;
}

function toArrayBuffer(bytes: Uint8Array<ArrayBufferLike>): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function buildEncryptedResponse(
  request: Request,
  serverIdentity: Identity,
  status = 200
): Promise<Response> {
  const requestEncHex = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER);
  assert(requestEncHex, `Missing ${PROTOCOL.ENCAPSULATED_KEY_HEADER} header`);
  const requestEnc = hexToBytes(requestEncHex);

  const encryptedRequestBody = new Uint8Array(await request.arrayBuffer());
  assert(encryptedRequestBody.byteLength >= 4, 'Encrypted request body must include chunk length');

  const chunkLength = new DataView(
    encryptedRequestBody.buffer,
    encryptedRequestBody.byteOffset,
    encryptedRequestBody.byteLength
  ).getUint32(0, false);
  assert.strictEqual(
    encryptedRequestBody.byteLength,
    4 + chunkLength,
    'Expected exactly one encrypted request chunk'
  );
  const ciphertext = encryptedRequestBody.slice(4);

  const suite = new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_256_GCM
  );
  const infoBytes = new TextEncoder().encode(HPKE_REQUEST_INFO);
  const recipientContext = await suite.SetupRecipient(serverIdentity.getPrivateKey(), requestEnc, {
    info: infoBytes,
  });

  const decryptedRequest = await recipientContext.Open(ciphertext);
  const decryptedText = new TextDecoder().decode(decryptedRequest);
  const responseText = `processed:${decryptedText}`;

  const responseNonce = new Uint8Array(RESPONSE_NONCE_LENGTH);
  crypto.getRandomValues(responseNonce);

  const exportLabelBytes = new TextEncoder().encode(EXPORT_LABEL);
  const exportedSecret = await recipientContext.Export(exportLabelBytes, EXPORT_LENGTH);
  const keyMaterial = await deriveResponseKeys(exportedSecret, requestEnc, responseNonce);

  const responseCiphertext = await encryptChunk(
    keyMaterial,
    0,
    new TextEncoder().encode(responseText)
  );

  return new Response(toArrayBuffer(encodeSingleChunk(responseCiphertext)), {
    status,
    headers: {
      [PROTOCOL.RESPONSE_NONCE_HEADER]: bytesToHex(responseNonce),
    },
  });
}

describe("custom EHBP network fetch", () => {
  afterEach(() => vi.restoreAllMocks());

  it("encrypts before calling the adapter and decrypts its streamed response", async () => {
    const server = await Identity.generate();
    const globalFetch = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("unexpected global fetch"));
    const controller = new AbortController();
    const send = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      expect(request.url).toBe("https://proxy.example/v1/chat/completions");
      expect(request.headers.get("X-Tinfoil-Enclave-Url")).toBe("https://enclave.example");
      expect(request.headers.get("authorization")).toBe("Bearer provider-key");
      expect(request.headers.has(PROTOCOL.ENCAPSULATED_KEY_HEADER)).toBe(true);
      expect(request.credentials).toBe("omit");
      expect(request.redirect).toBe("error");
      const wireBody = await request.clone().text();
      expect(wireBody).not.toContain("private prompt");
      expect(wireBody).not.toContain("private-cache-secret");
      const encrypted = await buildEncryptedResponse(request, server);
      controller.abort();
      expect(request.signal.aborted).toBe(true);
      const bytes = new Uint8Array(await encrypted.arrayBuffer());
      return new Response(new ReadableStream({
        start(stream) {
          stream.enqueue(bytes.slice(0, 3));
          stream.enqueue(bytes.slice(3));
          stream.close();
        },
      }), { headers: encrypted.headers });
    });
    const transport = await createSecureFetch("https://proxy.example", await server.getPublicKeyHex(),
      undefined, "https://enclave.example", "private-cache-secret", send);
    const response = await transport.fetch("/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer provider-key", "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "private prompt" }] }),
      credentials: "omit",
      redirect: "error",
      signal: controller.signal,
    });
    expect(await response.text()).toBe('processed:' + JSON.stringify({
      messages: [{ role: "user", content: "private prompt" }], user_cache_secret: "private-cache-secret",
    }));
    expect(send).toHaveBeenCalledTimes(1);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("rejects other origins without invoking the adapter", async () => {
    const send = vi.fn(async () => new Response());
    const server = await Identity.generate();
    const transport = await createSecureFetch("https://enclave.example", await server.getPublicKeyHex(),
      undefined, undefined, "", send);
    await expect(transport.fetch("https://other.example", { method: "POST", body: "secret" }))
      .rejects.toThrow("refusing to send request");
    expect(send).not.toHaveBeenCalled();
  });

  it("cannot substitute a custom fetch for certificate pinning", async () => {
    const send = vi.fn(async () => new Response());
    await expect(createSecureFetch("https://enclave.example", undefined, "fingerprint", undefined, "", send))
      .rejects.toThrow("Custom fetch requires an HPKE public key");
    expect(send).not.toHaveBeenCalled();
  });
});
