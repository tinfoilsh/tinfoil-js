import { afterEach, describe, expect, it, vi } from "vitest";
import { Identity, PROTOCOL, extractSessionRecoveryToken, deriveResponseKeys, encryptChunk, bytesToHex, serializeSessionRecoveryToken, deserializeSessionRecoveryToken, decryptResponseWithToken, type SessionRecoveryToken } from "ehbp";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch.js";
import { AttestationError, ConfigurationError } from "../src/errors.js";
afterEach(() => vi.restoreAllMocks());
async function context() {
  const identity = await Identity.generate(); let token!: SessionRecoveryToken; const tokens = new Map<string, SessionRecoveryToken>();
  const encrypt = Identity.prototype.encryptRequestWithContext;
  vi.spyOn(Identity.prototype, "encryptRequestWithContext").mockImplementation(async function (request) {
    const result = await encrypt.call(this, request);
    if (result.context) { token = await extractSessionRecoveryToken(result.context); tokens.set(new URL(request.url).pathname, token); }
    return result;
  });
  return { transport: createEncryptedBodyFetch("https://enclave.test", await identity.getPublicKeyHex()), token: () => token, tokens };
}
async function frame(token: SessionRecoveryToken, text: string) {
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const keys = await deriveResponseKeys(token.exportedSecret, token.requestEnc, nonce);
  const cipher = await encryptChunk(keys, 0, new TextEncoder().encode(text));
  const body = new Uint8Array(4 + cipher.length); new DataView(body.buffer).setUint32(0, cipher.length, false); body.set(cipher, 4);
  return { body, headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: bytesToHex(nonce) } };
}
describe("EHBP authenticated response lifetime", () => {
  it("decrypts a stream and preserves detached recovery-token format and lifetime", async () => {
    const setup = await context(); let envelope!: Awaited<ReturnType<typeof frame>>; let source!: ReadableStreamDefaultController<Uint8Array>;
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      envelope = await frame(setup.token(), "authenticated stream");
      return new Response(new ReadableStream({ start(controller) { source = controller; } }), { headers: envelope.headers });
    });
    const response = await setup.transport.fetch("/chat", { method: "POST", body: "private" });
    const token = await setup.transport.getSessionRecoveryToken(); const saved = serializeSessionRecoveryToken(token);
    token.exportedSecret.fill(0); expect(serializeSessionRecoveryToken(await setup.transport.getSessionRecoveryToken())).toBe(saved);
    source.enqueue(envelope.body); source.close(); expect(await response.text()).toBe("authenticated stream");
    await expect(setup.transport.getSessionRecoveryToken()).rejects.toBeInstanceOf(ConfigurationError);
    const recovered = await decryptResponseWithToken(new Response(envelope.body, { headers: envelope.headers }), deserializeSessionRecoveryToken(saved));
    expect(await recovered.text()).toBe("authenticated stream");
  });
  it("decrypts authenticated HTTP errors and classifies stream authentication failure", async () => {
    const setup = await context();
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      const envelope = await frame(setup.token(), "enclave diagnostic");
      return new Response(envelope.body, { status: 500, headers: envelope.headers });
    });
    const errorResponse = await setup.transport.fetch("/chat", { method: "POST", body: "private" });
    expect(errorResponse.status).toBe(500); expect(await errorResponse.text()).toBe("enclave diagnostic");
    vi.mocked(globalThis.fetch).mockImplementation(async () => {
      const envelope = await frame(setup.token(), "tampered"); envelope.body[envelope.body.length - 1] ^= 1;
      return new Response(envelope.body, { headers: envelope.headers });
    });
    const invalid = await setup.transport.fetch("/chat", { method: "POST", body: "private" });
    await expect(invalid.text()).rejects.toBeInstanceOf(AttestationError);
    await expect(setup.transport.getSessionRecoveryToken()).rejects.toBeInstanceOf(ConfigurationError);
  });
  it("keeps the latest request token when an older response arrives and completes later", async () => {
    const setup = await context(); let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const sources = new Map<string, ReadableStreamDefaultController<Uint8Array>>();
    const envelopes = new Map<string, Awaited<ReturnType<typeof frame>>>();
    vi.spyOn(globalThis, "fetch").mockImplementation(async input => {
      const path = new URL((input as Request).url).pathname;
      envelopes.set(path, await frame(setup.tokens.get(path)!, path));
      if (path === "/old") await gate;
      return new Response(new ReadableStream({ start(controller) { sources.set(path, controller); } }), { headers: envelopes.get(path)!.headers });
    });
    const old = setup.transport.fetch("/old", { method: "POST", body: "old" });
    await vi.waitFor(() => expect(envelopes.has("/old")).toBe(true));
    const latest = await setup.transport.fetch("/new", { method: "POST", body: "new" });
    const newestToken = serializeSessionRecoveryToken(await setup.transport.getSessionRecoveryToken());
    release(); const older = await old;
    expect(serializeSessionRecoveryToken(await setup.transport.getSessionRecoveryToken())).toBe(newestToken);
    sources.get("/old")!.enqueue(envelopes.get("/old")!.body); sources.get("/old")!.close(); expect(await older.text()).toBe("/old");
    expect(serializeSessionRecoveryToken(await setup.transport.getSessionRecoveryToken())).toBe(newestToken);
    sources.get("/new")!.enqueue(envelopes.get("/new")!.body); sources.get("/new")!.close(); expect(await latest.text()).toBe("/new");
    await expect(setup.transport.getSessionRecoveryToken()).rejects.toBeInstanceOf(ConfigurationError);
  });

});
