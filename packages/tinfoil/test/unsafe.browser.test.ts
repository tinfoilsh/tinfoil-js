/**
 * The unverified client in a browser: it fetches the key from the peer's
 * well-known path, seals a request to it, and warns on creation. The peer is
 * an EHBP peer behind a mocked fetch, since a page can't start a server.
 */
import { PROTOCOL } from "ehbp";
import { beforeAll, describe, expect, it } from "vitest";
import { ConfigurationError } from "../src/errors.js";
import { createUnverifiedClient } from "../src/internal/unsafe-client.js";
import { UNVERIFIED_WARNING } from "../src/unsafe.js";
import { createEhbpPeer, fetchOf, type EhbpPeer } from "./helpers/ehbp-peer.js";

const ORIGIN = "https://dev.example";
let peer: EhbpPeer;
let keyConfig: Uint8Array;

beforeAll(async () => {
  peer = await createEhbpPeer((seen) => {
    if (seen.path === PROTOCOL.KEYS_PATH) return { headers: { "content-type": PROTOCOL.KEYS_MEDIA_TYPE }, body: keyConfig, plaintext: true };
    return { headers: { "content-type": "application/json" }, body: JSON.stringify({ path: seen.path, sealed: seen.sealed, text: new TextDecoder().decode(seen.body) }) };
  });
  keyConfig = await peer.identity.marshalConfig();
});

describe("UnverifiedClient in a browser", () => {
  it("warns, fetches the key, and seals a request to it", async () => {
    const warnings: string[] = [];
    const client = await createUnverifiedClient({ baseURL: `${ORIGIN}/v1/` }, { fetch: fetchOf(peer), warn: (m) => warnings.push(m) });
    expect(warnings).toEqual([UNVERIFIED_WARNING]);
    expect(peer.seen.map((s) => s.path)).toEqual([PROTOCOL.KEYS_PATH]);
    const response = await client.fetch("/v1/echo", { method: "POST", body: "hello" });
    expect(await response.json()).toEqual({ path: "/v1/echo", sealed: true, text: "hello" });
    await expect(client.fetch("https://other.example/v1/echo")).rejects.toThrow(ConfigurationError);
  });
});
