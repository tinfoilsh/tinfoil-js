/**
 * Bun compatibility tests
 * Run with: bun test test/bun-compat.bun.ts
 *
 * These tests verify that the TLS pinning fallback works correctly in Bun,
 * since Bun doesn't support X25519 in WebCrypto's crypto.subtle API.
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

  describe("X25519 WebCrypto", () => {
    it("should fail deriveBits with NotSupportedError (expected in Bun)", async () => {
      if (!isBun) return;

      // Key generation works in Bun
      const keyPair = await crypto.subtle.generateKey(
        { name: "X25519" },
        true,
        ["deriveBits", "deriveKey"]
      );
      expect(keyPair).toBeDefined();

      const otherKeyPair = await crypto.subtle.generateKey(
        { name: "X25519" },
        true,
        ["deriveBits", "deriveKey"]
      );

      // But deriveBits fails - this is why we need TLS fallback
      try {
        await crypto.subtle.deriveBits(
          { name: "X25519", public: otherKeyPair.publicKey },
          keyPair.privateKey,
          256
        );
        // If we get here, Bun has added X25519 support
        console.log("X25519 deriveBits now works in Bun - EHBP should work!");
      } catch (error) {
        expect((error as Error).name).toBe("NotSupportedError");
      }
    });
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
    it("should create a working fetch function", async () => {
      if (!isBun) return;

      const pinnedFetch = await createPinnedTlsFetch(
        "https://example.com",
        "0000000000000000000000000000000000000000000000000000000000000000"
      );

      expect(typeof pinnedFetch).toBe("function");
    });

    it("should reject HTTP connections", async () => {
      if (!isBun) return;

      const pinnedFetch = await createPinnedTlsFetch(
        "http://example.com",
        "0000000000000000000000000000000000000000000000000000000000000000"
      );

      await expect(pinnedFetch("/test")).rejects.toThrow("HTTP connections are not allowed");
    });

    it("should reject mismatched certificate fingerprints", async () => {
      if (!isBun) return;

      // Use a different host to avoid connection reuse from previous tests
      const pinnedFetch = await createPinnedTlsFetch(
        "https://www.google.com",
        "0000000000000000000000000000000000000000000000000000000000000000"
      );

      await expect(pinnedFetch("/")).rejects.toThrow("fingerprint mismatch");
    });
  });
});
