/**
 * Session recovery on the EHBP transport against a local EHBP server: a
 * sealed response carries a token, the token survives serialization, it
 * opens the sealed form of the same response without the client, including
 * a streamed one, and responses that were never sealed have no token.
 */
import { AeadDecryptFailedError, Identity, PROTOCOL } from "ehbp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConfigurationError } from "../src/errors.js";
import { ehbpMode } from "../src/internal/transport/ehbp.js";
import { PeerLacksKeyError } from "../src/internal/transport/transport.js";
import type { Fetch } from "../src/options.js";
import { decryptResponseWithToken, deserializeSessionRecoveryToken, serializeSessionRecoveryToken, sessionRecoveryToken } from "../src/session-recovery.js";
import { KEY_X25519_HPKE_V1_FORMAT, type Verification } from "../../verifier/src/index.js";
import { paced, startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";

let server: EhbpServer;

function verification(hpke: string): Verification {
  return {
    cryptoMaterial: () => [{ id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke }],
    tlsPublicKeyFP: () => "ab".repeat(32),
    hpkePublicKey: () => hpke,
    freshnessExpiresAt: () => new Date(Date.now() + 60_000),
  } as unknown as Verification;
}

/**
 * A fetch that keeps the sealed form of every response it returns, as a
 * relay forwarding the exchange would hold it: a clone, with the same
 * status and headers over a copy of the body the client never opened.
 */
function recording(): { fetch: Fetch; sealed: Response[] } {
  const sealed: Response[] = [];
  return {
    sealed,
    fetch: async (input, init) => {
      const response = await fetch(input, init);
      sealed.push(response.clone());
      return response;
    },
  };
}

async function text(response: Response): Promise<string> {
  return new TextDecoder().decode(new Uint8Array(await response.arrayBuffer()));
}

beforeAll(async () => {
  server = await startEhbpServer((seen) => {
    switch (seen.path) {
      case "/echo":
        return { headers: { "content-type": "text/plain" }, body: `echo: ${new TextDecoder().decode(seen.body)}` };
      case "/sse":
        return { headers: { "content-type": "text/event-stream" }, body: paced(["data: 1\n\n", "data: 2\n\n", "data: 3\n\n"], 40) };
      case "/plain":
        return { headers: { "content-type": "text/plain" }, body: "hello" };
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

describe("sessionRecoveryToken", () => {
  it("gives a sealed response a token that opens its sealed form without the client, and survives serialization", async () => {
    const relay = recording();
    const bound = await ehbpMode({ fetch: relay.fetch }).bind(verification(server.publicKeyHex));
    const response = await bound.fetch(`${server.origin}/echo`, { method: "POST", body: "secret prompt" });
    expect(await text(response)).toBe("echo: secret prompt");

    const token = await sessionRecoveryToken(response);
    expect(token.exportedSecret).toBeInstanceOf(Uint8Array);
    expect(token.requestEnc).toBeInstanceOf(Uint8Array);
    expect(token.requestEnc.length).toBe(32);

    // The token is plain bytes: a JSON round trip gives an equal token.
    const restored = deserializeSessionRecoveryToken(serializeSessionRecoveryToken(token));
    expect(restored).toEqual(token);

    // The relay holds the sealed form; the restored token alone opens it.
    const sealed = relay.sealed[relay.sealed.length - 1]!;
    expect(sealed.headers.has(PROTOCOL.RESPONSE_NONCE_HEADER)).toBe(true);
    const opened = await decryptResponseWithToken(sealed, restored);
    expect(await text(opened)).toBe("echo: secret prompt");
  });

  it("opens a streamed response chunk by chunk from its token, after the client has read it", async () => {
    const relay = recording();
    const bound = await ehbpMode({ fetch: relay.fetch }).bind(verification(server.publicKeyHex));
    const response = await bound.fetch(`${server.origin}/sse`, { method: "POST", body: "start" });
    // The token is available as soon as the response headers are, before any of the stream is read.
    const token = serializeSessionRecoveryToken(await sessionRecoveryToken(response));
    expect(await text(response)).toBe("data: 1\n\ndata: 2\n\ndata: 3\n\n");

    const opened = await decryptResponseWithToken(relay.sealed[relay.sealed.length - 1]!, deserializeSessionRecoveryToken(token));
    const reader = opened.body!.getReader();
    const decoder = new TextDecoder();
    const chunks: string[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(decoder.decode(value));
    }
    expect(chunks).toEqual(["data: 1\n\n", "data: 2\n\n", "data: 3\n\n"]);
  });

  it("gives each response its own token, so one request's token does not open another's response", async () => {
    const relay = recording();
    const bound = await ehbpMode({ fetch: relay.fetch }).bind(verification(server.publicKeyHex));
    const first = await bound.fetch(`${server.origin}/echo`, { method: "POST", body: "one" });
    const second = await bound.fetch(`${server.origin}/echo`, { method: "POST", body: "two" });
    const [tokenOne, tokenTwo] = await Promise.all([sessionRecoveryToken(first), sessionRecoveryToken(second)]);
    expect(tokenOne).not.toEqual(tokenTwo);
    await Promise.all([first.arrayBuffer(), second.arrayBuffer()]);

    const sealedSecond = relay.sealed[relay.sealed.length - 1]!;
    const wrongly = await decryptResponseWithToken(sealedSecond, tokenOne);
    await expect(wrongly.arrayBuffer()).rejects.toBeInstanceOf(AeadDecryptFailedError);
  });

  it("has no token for a response that was never sealed", async () => {
    const bound = await ehbpMode().bind(verification(server.publicKeyHex));
    const plain = await bound.fetch(`${server.origin}/plain`);
    expect(await plain.text()).toBe("hello");
    await expect(sessionRecoveryToken(plain)).rejects.toThrow(ConfigurationError);
    await expect(sessionRecoveryToken(plain)).rejects.toThrow(/not opened from a sealed exchange/);

    const error = await bound.fetch(`${server.origin}/error`, { method: "POST", body: "x" });
    expect(error.status).toBe(503);
    await expect(sessionRecoveryToken(error)).rejects.toThrow(ConfigurationError);

    await expect(sessionRecoveryToken(new Response("unrelated"))).rejects.toThrow(ConfigurationError);
  });

  it("has no token for an attempt the peer rejects for a stale key; a fresh request under the right key gets one", async () => {
    // The peer refuses a stale key before any response is opened, so that
    // attempt yields no response and no token.
    const other = await (await Identity.generate()).getPublicKeyHex();
    const stale = await ehbpMode().bind(verification(other));
    await expect(stale.fetch(`${server.origin}/echo`, { method: "POST", body: "x" })).rejects.toBeInstanceOf(PeerLacksKeyError);
    const fresh = await ehbpMode().bind(verification(server.publicKeyHex));
    const response = await fresh.fetch(`${server.origin}/echo`, { method: "POST", body: "x" });
    expect(await text(response)).toBe("echo: x");
    expect((await sessionRecoveryToken(response)).requestEnc.length).toBe(32);
  });
});
