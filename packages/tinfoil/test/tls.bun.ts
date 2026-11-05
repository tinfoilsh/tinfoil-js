/**
 * The TLS transport under Bun, against a local HTTPS server: a matching pin
 * serves, a mismatch fails closed, plaintext is refused.
 * Run with: bun test test/tls.bun.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { ConfigurationError } from "../src/errors.js";
import { tlsMode } from "../src/internal/transport/tls.js";
import { PeerLacksKeyError } from "../src/internal/transport/transport.js";
import type { Verification } from "@tinfoilsh/verifier";

const cert = readFileSync(new URL("./fixtures/ws-test-cert.pem", import.meta.url), "utf8");
const key = readFileSync(new URL("./fixtures/ws-test-key.pem", import.meta.url), "utf8");
const PIN = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");

function verification(fp: string): Verification {
  return {
    cryptoMaterial: () => [{ id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: fp }],
    tlsPublicKeyFP: () => fp,
    hpkePublicKey: () => undefined,
    freshnessExpiresAt: () => new Date(Date.now() + 60_000),
  } as unknown as Verification;
}

let server: ReturnType<typeof Bun.serve>;
let origin: string;
let requests = 0;

beforeAll(() => {
  server = Bun.serve({
    hostname: "localhost",
    port: 0,
    tls: { key, cert },
    fetch() {
      requests++;
      return new Response("hello");
    },
  });
  origin = `https://localhost:${server.port}`;
});

afterAll(() => {
  server.stop(true);
});

describe("tlsMode under Bun", () => {
  const mode = tlsMode({ ca: cert });

  it("serves when the certificate carries the pinned key", async () => {
    const bound = await mode.bind(verification(PIN));
    const res = await bound.fetch(`${origin}/plain`);
    expect(await res.text()).toBe("hello");
  });

  it("fails closed when the certificate carries another key, without the request reaching the server", async () => {
    const before = requests;
    const bound = await mode.bind(verification("ab".repeat(32)));
    const err = await bound.fetch(`${origin}/never`).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PeerLacksKeyError);
    expect(requests).toBe(before);
  });

  it("refuses plaintext", async () => {
    const bound = await mode.bind(verification(PIN));
    await expect(bound.fetch("http://localhost/")).rejects.toBeInstanceOf(ConfigurationError);
  });
});
