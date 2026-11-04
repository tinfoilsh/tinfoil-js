/**
 * The transport layers above a mode: origin restriction, the proxy header,
 * the single replay, and the keyed transport that ties requests to the
 * current verification and turns a peer's key rejection into a replayable
 * rejection after invalidating that verification.
 */
import { describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, NetworkError } from "../../src/v3/errors.js";
import { Enclave } from "../../src/v3/internal/enclave.js";
import { ENCLAVE_URL_HEADER, enclaveURLHeaderValue, withEnclaveURL } from "../../src/v3/internal/transport/header.js";
import { allowedOrigins, normalizedOrigin, originOf, requestURL, withOriginRestriction } from "../../src/v3/internal/transport/origin.js";
import { withReplay } from "../../src/v3/internal/transport/replay.js";
import { isKeyRejection, KeyedTransport, KeyRejectionError, PeerLacksKeyError, type Mode } from "../../src/v3/internal/transport/transport.js";
import type { Fetch } from "../../src/v3/options.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, type Verification, type Verifier } from "../../../verifier/src/v3/index.js";

const HOST = "enclave.example";

/** A fetch that records its calls and answers 200. */
function recording(): { fetch: Fetch; calls: { url: string; init: RequestInit | undefined }[] } {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  return {
    calls,
    fetch: async (input, init) => {
      calls.push({ url: input instanceof Request ? input.url : String(input), init });
      return new Response("ok");
    },
  };
}

describe("origins", () => {
  it("normalizes scheme, host and default ports", () => {
    expect(originOf("HTTPS://Enclave.Example:443/v1/")).toBe("https://enclave.example");
    expect(originOf("https://enclave.example:8443/x")).toBe("https://enclave.example:8443");
    expect(originOf("http://localhost:80/")).toBe("http://localhost");
    expect(normalizedOrigin(new URL("https://[::1]:8443/"))).toBe("https://[::1]:8443");
    for (const bad of ["/relative", "ftp://x/", "enclave.example"]) expect(() => originOf(bad), bad).toThrow();
    expect(() => requestURL("/relative")).toThrow(ConfigurationError);
  });

  it("allows the enclave's origin and the base URL's, either of which may be absent", () => {
    expect([...allowedOrigins(HOST, "")]).toEqual([`https://${HOST}`]);
    expect([...allowedOrigins(HOST, "https://proxy.example/v1/")]).toEqual([`https://${HOST}`, "https://proxy.example"]);
    expect([...allowedOrigins("", "https://gateway.example/v1/")]).toEqual(["https://gateway.example"]);
    expect(() => allowedOrigins(HOST, "not a url")).toThrow(ConfigurationError);
  });

  it("refuses a request to any other origin before it is sent", async () => {
    const { fetch, calls } = recording();
    const guarded = withOriginRestriction(fetch, HOST, "https://proxy.example/v1/");
    await guarded(`https://${HOST}/v1/models`);
    await guarded(new URL("https://proxy.example:443/v1/chat"));
    await guarded(new Request("https://PROXY.example/v1/chat"));
    await expect(guarded("https://other.example/v1/models")).rejects.toThrow(ConfigurationError);
    await expect(guarded(`http://${HOST}/v1/models`)).rejects.toThrow(/refusing to send request to "http:\/\/enclave.example": client is bound to enclave "enclave.example"/);
    expect(calls).toHaveLength(3);
  });
});

describe("the enclave URL header", () => {
  it("is set only when the base URL is a proxy on another origin", () => {
    expect(enclaveURLHeaderValue(HOST, "")).toBeUndefined();
    expect(enclaveURLHeaderValue(HOST, `https://${HOST}/v1/`)).toBeUndefined();
    expect(enclaveURLHeaderValue(HOST, `https://${HOST}:443/`)).toBeUndefined();
    expect(enclaveURLHeaderValue(HOST, "https://proxy.example/")).toBe(`https://${HOST}`);
    expect(enclaveURLHeaderValue("", "https://proxy.example/")).toBeUndefined();
  });

  it("adds the header to every proxied request, keeping the caller's headers", async () => {
    const { fetch, calls } = recording();
    const direct = withEnclaveURL(fetch, HOST, "");
    expect(direct).toBe(fetch);
    const proxied = withEnclaveURL(fetch, HOST, "https://proxy.example/");
    await proxied("https://proxy.example/v1/chat", { headers: { Authorization: "Bearer k" } });
    await proxied(new Request("https://proxy.example/v1/chat", { headers: { "x-custom": "1" } }));
    const sent = calls.map((c) => new Headers(c.init?.headers));
    expect(sent[0]!.get(ENCLAVE_URL_HEADER)).toBe(`https://${HOST}`);
    expect(sent[0]!.get("authorization")).toBe("Bearer k");
    expect(sent[1]!.get(ENCLAVE_URL_HEADER)).toBe(`https://${HOST}`);
    expect(sent[1]!.get("x-custom")).toBe("1");
  });
});

describe("replay", () => {
  const rejected = (): PeerLacksKeyError => new PeerLacksKeyError("stale key");
  const retryable = (err: unknown): boolean => err instanceof PeerLacksKeyError;

  /** A fetch that fails `failures` times, then answers with the body it received. */
  function flaky(failures: number): { fetch: Fetch; bodies: string[] } {
    const bodies: string[] = [];
    let remaining = failures;
    return {
      bodies,
      fetch: async (input, init) => {
        const body = init?.body !== undefined && init.body !== null ? await new Response(init.body as BodyInit).text() : input instanceof Request ? await input.text() : "";
        bodies.push(body);
        if (remaining-- > 0) throw rejected();
        return new Response("ok");
      },
    };
  }

  it("sends a request again once after a retryable failure, with the same body", async () => {
    const { fetch, bodies } = flaky(1);
    const replayed = withReplay(fetch, retryable);
    expect(await (await replayed("https://x.example/", { method: "POST", body: "payload" })).text()).toBe("ok");
    expect(bodies).toEqual(["payload", "payload"]);
    const viaRequest = flaky(1);
    expect(await (await withReplay(viaRequest.fetch, retryable)(new Request("https://x.example/", { method: "POST", body: "again" }))).text()).toBe("ok");
    expect(viaRequest.bodies).toEqual(["again", "again"]);
  });

  it("does not replay a non-retryable failure, a streaming body, or an aborted request, and reports a failed replay with both failures", async () => {
    const network = withReplay(async () => {
      throw new NetworkError("down");
    }, retryable);
    await expect(network("https://x.example/")).rejects.toThrow(/^network error: down$/);

    const streaming = withReplay(flaky(1).fetch, retryable);
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode("s"));
        c.close();
      },
    });
    const err = await streaming("https://x.example/", { method: "POST", body: stream }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PeerLacksKeyError);
    expect((err as Error).message).toBe("attestation error: stale key; cannot replay the request after key rotation: body is not replayable");

    const controller = new AbortController();
    const aborted = withReplay(async () => {
      controller.abort();
      throw rejected();
    }, retryable);
    await expect(aborted("https://x.example/", { signal: controller.signal })).rejects.toThrow(/request aborted before it could be replayed/);

    const twice = withReplay(flaky(2).fetch, retryable);
    await expect(twice("https://x.example/")).rejects.toThrow(/^attestation error: stale key; the replay failed too; first attempt: attestation error: stale key$/);
  });
});

describe("KeyedTransport", () => {
  /** A verifier whose verifications carry the TLS fingerprint `keys` yields, one per verification. */
  function keyedVerifier(keys: () => string, expiresAt: Date): Verifier {
    return {
      checkRepoVerifiability: () => {},
      verifyV3At: async () => {
        const key = keys();
        return {
          cryptoMaterial: () => [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: key }],
          cryptoMaterialData: (id: string) => (id === "tls" ? key : undefined),
          tlsPublicKeyFP: () => key,
          hpkePublicKey: () => undefined,
          freshnessExpiresAt: () => new Date(expiresAt.getTime()),
        } as unknown as Verification;
      },
    } as unknown as Verifier;
  }

  /** A mode whose bound fetch answers with the key it was bound to, or rejects the peer when `peerKey` differs. */
  function fakeMode(peerKey: () => string, closed: string[]): Mode {
    return {
      name: "tls",
      validateRequest(request) {
        if (request.url.protocol !== "https:") throw new ConfigurationError("needs https");
      },
      bind(v) {
        const key = v.tlsPublicKeyFP()!;
        return {
          fetch: async () => {
            if (peerKey() !== key) throw new PeerLacksKeyError("peer changed key");
            return new Response(key);
          },
          close: () => void closed.push(key),
        };
      },
    };
  }

  async function transport(keys: () => string, peerKey: () => string, closed: string[] = []): Promise<KeyedTransport> {
    const now = new Date("2026-01-01T00:00:00Z");
    const enclave = await Enclave.create({
      host: HOST,
      repo: "",
      verifier: keyedVerifier(keys, new Date(now.getTime() + 60_000)),
      fetch: async () => new Response(new Uint8Array([1])),
      clock: () => now,
      sleep: async () => {},
    });
    return new KeyedTransport(enclave, fakeMode(peerKey, closed), () => now);
  }

  it("verifies on the first request, binds the mode to the verification's key, and validates before verifying", async () => {
    const t = await transport(
      () => "k1",
      () => "k1",
    );
    expect(t.current()).toBeUndefined();
    expect(t.mode()).toBe("tls");
    await expect(t.fetch(`http://${HOST}/`)).rejects.toThrow(ConfigurationError);
    expect(t.current()).toBeUndefined();
    expect(await (await t.fetch(`https://${HOST}/v1/models`)).text()).toBe("k1");
    expect(t.current()?.tlsPublicKeyFP()).toBe("k1");
    expect((await t.ensureVerified()).tlsPublicKeyFP()).toBe("k1");
  });

  it("turns a peer's key rejection into a replayable rejection after invalidating the verification, so the replay goes out under a fresh one", async () => {
    let verified = 0;
    const peer = { key: "k2" };
    const closed: string[] = [];
    const t = await transport(
      () => (verified++ === 0 ? "k1" : "k2"),
      () => peer.key,
      closed,
    );
    const err = await t.fetch(`https://${HOST}/v1/chat`).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KeyRejectionError);
    expect(err).toBeInstanceOf(AttestationError);
    expect(isKeyRejection(err)).toBe(true);
    expect((err as Error).message).toBe("attestation error: peer changed key");
    expect(isKeyRejection(new PeerLacksKeyError("alone"))).toBe(false);

    const replayed = withReplay(t.fetch, isKeyRejection);
    expect(await (await replayed(`https://${HOST}/v1/chat`)).text()).toBe("k2");
    expect(verified).toBe(2);
    expect(closed).toEqual(["k1"]);
    expect((await t.reverify()).tlsPublicKeyFP()).toBe("k2");
    expect(closed).toEqual(["k1", "k2"]);
  });
});
