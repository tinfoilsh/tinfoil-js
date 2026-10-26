/**
 * Bun compatibility tests
 * Run with: bun test test/bun-compat.bun.ts
 *
 * These tests verify TLS pinning works correctly in Bun.
 *
 * Note: Some TLS-related tests may be flaky due to Bun's connection pooling.
 * The tests use different hostnames to avoid connection reuse issues.
 */

import { describe, it, expect, beforeAll } from "bun:test";
import { createPinnedTlsFetch } from "../src/pinned-tls-fetch.js";

const isBun = typeof process !== "undefined" && (process as any).versions?.bun;

describe("Bun compatibility", () => {
  beforeAll(() => {
    if (!isBun) {
      console.log("Skipping Bun-specific tests (not running in Bun)");
    }
  });

  describe("TLS pinning via fetch", () => {
    it("should invoke checkServerIdentity callback and provide cert.raw", async () => {
      if (!isBun) return;

      let callbackInvoked = false;
      let receivedHostname = "";
      let certRaw: Buffer | undefined;

      const response = await fetch("https://example.com", {
        // @ts-ignore - Bun-specific TLS options
        tls: {
          checkServerIdentity: (hostname: string, cert: any) => {
            callbackInvoked = true;
            receivedHostname = hostname;
            certRaw = cert?.raw;
            return undefined;
          },
        },
      });

      expect(callbackInvoked).toBe(true);
      expect(receivedHostname).toBe("example.com");
      expect(response.ok).toBe(true);
      expect(certRaw).toBeDefined();
      expect(certRaw!.length).toBeGreaterThan(0);
    });

    it("should be able to reject connections via checkServerIdentity", async () => {
      if (!isBun) return;

      // Use a different host to avoid connection reuse
      await expect(
        fetch("https://httpbin.org/get", {
          // @ts-ignore - Bun-specific TLS options
          tls: {
            checkServerIdentity: () => {
              return new Error("Intentional rejection for testing");
            },
          },
        })
      ).rejects.toThrow("Intentional rejection");
    });
  });

  describe("createPinnedTlsFetch", () => {
    it("should reject mismatched certificate fingerprints on first request", async () => {
      if (!isBun) return;

      const wrongFingerprint = "0000000000000000000000000000000000000000000000000000000000000000";
      const pinnedFetch = await createPinnedTlsFetch("https://www.cloudflare.com", wrongFingerprint);

      await expect(pinnedFetch("/")).rejects.toThrow("attested key");
    });

    it("should reject HTTP connections during creation", async () => {
      if (!isBun) return;

      await expect(
        createPinnedTlsFetch(
          "http://example.com",
          "0000000000000000000000000000000000000000000000000000000000000000"
        )
      ).rejects.toThrow("must be HTTPS");
    });

    it("should verify certificate on every request", async () => {
      if (!isBun) return;

      // This is the critical test: ensure checkServerIdentity is called on EVERY
      // request, not just the first. This prevents bypasses when the connection
      // pool times out and a new connection is established.
      //
      // We verify this by checking that new connections (forced via keepalive:false)
      // still invoke the checkServerIdentity callback.

      let verifyCallCount = 0;

      // First request with keepalive:false - should verify
      await fetch("https://example.org", {
        // @ts-ignore
        keepalive: false,
        tls: {
          checkServerIdentity: () => {
            verifyCallCount++;
            return undefined;
          },
        },
      });
      expect(verifyCallCount).toBe(1);

      // Second request with keepalive:false forces new connection - must verify again
      // If this doesn't increment, new connections bypass verification
      await fetch("https://example.org", {
        // @ts-ignore
        keepalive: false,
        tls: {
          checkServerIdentity: () => {
            verifyCallCount++;
            return undefined;
          },
        },
      });
      expect(verifyCallCount).toBe(2);
    });

    it("should reject wrong fingerprint even with warm connection pool", async () => {
      if (!isBun) return;

      // This test catches a security bug where connection pooling could bypass
      // certificate pinning. Even if a connection to the host already exists,
      // we must still verify the fingerprint.

      const wrongFingerprint = "0000000000000000000000000000000000000000000000000000000000000000";

      // Warm up the connection pool
      await fetch("https://www.wikipedia.org");

      // Create pinned fetch and make a request - should still verify and fail
      const pinnedFetch = await createPinnedTlsFetch("https://www.wikipedia.org", wrongFingerprint);
      await expect(pinnedFetch("/")).rejects.toThrow("attested key");
    });
  });
});

describe("Bun immutable pin bindings on actual HTTPS", () => {
  it("does not reuse ordinary or previously pinned connections under a different key", async () => {
    const { createServer } = await import("node:https");
    const { readFileSync } = await import("node:fs");
    const { X509Certificate, createHash } = await import("node:crypto");
    const { fileURLToPath } = await import("node:url");
    const certPath = fileURLToPath(new URL("./fixtures/ws-test-cert.pem", import.meta.url));
    const cert = readFileSync(certPath), key = readFileSync(new URL("./fixtures/ws-test-key.pem", import.meta.url));
    const fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
    let received = 0;
    const server = createServer({ cert, key }, (_request, response) => { received++; response.end("accepted"); });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address() as { port: number };
    const endpoint = `https://127.0.0.1:${address.port}`;
    const module = fileURLToPath(new URL("../src/pinned-tls-fetch.ts", import.meta.url));
    const script = `
      import { createPinnedTlsFetch } from ${JSON.stringify(module)};
      const endpoint = ${JSON.stringify(endpoint)};
      await (await fetch(endpoint)).text();
      const good = await createPinnedTlsFetch(endpoint, ${JSON.stringify(fingerprint)});
      await (await good('/')).text();
      const bad = await createPinnedTlsFetch(endpoint, '0'.repeat(64));
      for (let i = 0; i < 2; i++) {
        let rejected = false;
        try { await bad('/', { method: 'POST', body: 'must never be sent' }); }
        catch (error) { rejected = error.name === 'AttestationError'; }
        if (!rejected) throw new Error('Wrong attested key accepted after pooled connection');
      }
    `;
    try {
      const process = Bun.spawn([Bun.which("bun")!, "--eval", script], { env: { ...globalThis.process.env, NODE_EXTRA_CA_CERTS: certPath }, stdout: "pipe", stderr: "pipe" });
      const [exit, error] = await Promise.all([process.exited, new Response(process.stderr).text()]);
      expect(error).toBe(""); expect(exit).toBe(0); expect(received).toBe(2);
    } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  });
});
