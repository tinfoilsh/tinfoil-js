/**
 * The unverified client on a local EHBP server: it warns on creation,
 * fetches the key from the server's well-known path and nothing else, seals
 * bodies to it, resolves relative URLs against the base URL, refuses other
 * origins, names the key origin to a proxy, and reports a bad key response
 * as a network error. The entry exports only this client.
 */
import { PROTOCOL } from "ehbp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConfigurationError, NetworkError } from "../../src/v3/errors.js";
import * as unsafe from "../../src/v3/unsafe.js";
import { createUnverifiedClient, UNVERIFIED_WARNING, UnverifiedClient } from "../../src/v3/unsafe.js";
import { startEhbpServer, type EhbpServer } from "./helpers/ehbp-server.js";

let server: EhbpServer;
let keyConfig: Uint8Array;
let keyAnswer: "config" | "status-500" | "wrong-type" | "garbage" = "config";

beforeAll(async () => {
  server = await startEhbpServer((seen) => {
    if (seen.path === PROTOCOL.KEYS_PATH) {
      switch (keyAnswer) {
        case "status-500":
          return { status: 500, body: "nope", plaintext: true };
        case "wrong-type":
          return { headers: { "content-type": "text/plain" }, body: keyConfig, plaintext: true };
        case "garbage":
          return { headers: { "content-type": PROTOCOL.KEYS_MEDIA_TYPE }, body: new Uint8Array([1, 2, 3]), plaintext: true };
        default:
          return { headers: { "content-type": PROTOCOL.KEYS_MEDIA_TYPE }, body: keyConfig, plaintext: true };
      }
    }
    return {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path: seen.path, sealed: seen.sealed, text: new TextDecoder().decode(seen.body), enclave: seen.headers["x-tinfoil-enclave-url"] ?? null }),
    };
  });
  keyConfig = await server.identity.marshalConfig();
});

afterAll(async () => {
  await server.close();
});

/** Creates a client with a counting fetch and a captured warning. */
async function client(options: unsafe.UnverifiedOptions): Promise<{ client: UnverifiedClient; warnings: string[]; requested: string[] }> {
  const warnings: string[] = [];
  const requested: string[] = [];
  const c = await createUnverifiedClient(options, {
    warn: (m) => warnings.push(m),
    fetch: (input, init) => {
      requested.push(input instanceof Request ? input.url : String(input));
      return fetch(input, init);
    },
  });
  return { client: c, warnings, requested };
}

describe("UnverifiedClient", () => {
  it("warns once per client, fetches the key from the well-known path, and seals requests to it", async () => {
    const { client: c, warnings, requested } = await client({ baseURL: `${server.origin}/v1/` });
    expect(warnings).toEqual([UNVERIFIED_WARNING]);
    expect(requested).toEqual([`${server.origin}${PROTOCOL.KEYS_PATH}`]);
    expect(requested.some((u) => u.includes("tinfoil-attestation"))).toBe(false);
    expect(c.baseURL()).toBe(`${server.origin}/v1/`);
    expect(c.keyOrigin()).toBe(server.origin);

    const response = await c.fetch("/v1/chat/completions", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hi: 1 }) });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ path: "/v1/chat/completions", sealed: true, text: '{"hi":1}', enclave: null });
    expect(server.seen[server.seen.length - 1]?.sealed).toBe(true);
    // The key was fetched once, before the client was returned.
    expect(requested.filter((u) => u.endsWith(PROTOCOL.KEYS_PATH))).toHaveLength(1);
  });

  it("derives the base URL from the key origin and the key origin from the base URL", async () => {
    const fromKey = await client({ keyOrigin: server.origin });
    expect(fromKey.client.baseURL()).toBe(`${server.origin}/v1/`);
    const fromBase = await client({ baseURL: `${server.origin}/api/` });
    expect(fromBase.client.keyOrigin()).toBe(server.origin);
    const response = await fromBase.client.fetch("models");
    expect(await response.json()).toMatchObject({ path: "/api/models", sealed: false });
  });

  it("names the key origin to a proxy and keeps requests on the proxy", async () => {
    // The server stands in for the proxy; the key origin is spelled differently so the origins differ.
    const keyOrigin = server.origin.replace("127.0.0.1", "localhost");
    const { client: c } = await client({ baseURL: `${server.origin}/v1/`, keyOrigin });
    const response = await c.fetch("/v1/echo", { method: "POST", body: "x" });
    expect(await response.json()).toMatchObject({ sealed: true, enclave: keyOrigin });
    await expect(c.fetch(`${keyOrigin}/v1/echo`)).rejects.toThrow(ConfigurationError);
  });

  it("refuses requests to any other origin and absolute requests off the base origin", async () => {
    const { client: c } = await client({ baseURL: `${server.origin}/v1/` });
    await expect(c.fetch("https://other.example/v1/x")).rejects.toThrow(/refusing to send request/);
    await expect(c.fetch(new Request("https://other.example/v1/x"))).rejects.toThrow(ConfigurationError);
  });

  it("checks its options before any network I/O", async () => {
    const requested: string[] = [];
    const seams = {
      warn: () => {},
      fetch: (input: string | URL | Request, init?: RequestInit) => {
        requested.push(String(input));
        return fetch(input, init);
      },
    };
    await expect(createUnverifiedClient({}, seams)).rejects.toThrow(/needs a baseURL or a keyOrigin/);
    await expect(createUnverifiedClient({ baseURL: "http://10.0.0.1/v1/" }, seams)).rejects.toThrow(ConfigurationError);
    await expect(createUnverifiedClient({ keyOrigin: "not a url" }, seams)).rejects.toThrow(ConfigurationError);
    await expect(createUnverifiedClient({ keyOrigin: "https://user:pw@key.example" }, seams)).rejects.toThrow(ConfigurationError);
    expect(requested).toEqual([]);
  });

  it("reports a server that doesn't serve a usable key as a network error", async () => {
    for (const answer of ["status-500", "wrong-type", "garbage"] as const) {
      keyAnswer = answer;
      try {
        await expect(client({ baseURL: `${server.origin}/v1/` })).rejects.toThrow(NetworkError);
      } finally {
        keyAnswer = "config";
      }
    }
  });

  it("is constructed only through its factory", () => {
    expect(() => new UnverifiedClient(Symbol("x"), "", "", fetch)).toThrow(/created with UnverifiedClient.create/);
    expect(Object.getOwnPropertyNames(UnverifiedClient).filter((n) => !["length", "name", "prototype"].includes(n))).toEqual(["create"]);
  });
});

describe("the unsafe entry", () => {
  it("exports the client, its warning and nothing of the attested surface", () => {
    expect(Object.keys(unsafe).sort()).toEqual(["UNVERIFIED_WARNING", "UnverifiedClient", "checkUnverifiedOptions", "createUnverifiedClient"]);
    expect(UNVERIFIED_WARNING).toMatch(/insecure/i);
  });
});
