import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { encryptedBodyRequest, normalizeEncryptedBodyRequestArgs, getServerIdentity, createEncryptedBodyFetch, createUnverifiedEncryptedBodyFetch } from "../src/encrypted-body-fetch";
import { Identity, PROTOCOL } from "ehbp";

describe("encrypted-body-fetch", () => {
  describe("getServerIdentity", () => {
    it("rejects non-HTTPS URLs", async () => {
      await expect(getServerIdentity("http://example.com/v1")).rejects.toThrow(
        /HTTPS is required for key retrieval/
      );
    });

    it("rejects invalid content-type", async () => {
      const fetchMock = vi.fn(async () => {
        return new Response(new Uint8Array([1, 2, 3]), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      });

      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchMock as typeof fetch;

      try {
        await expect(getServerIdentity("https://example.com/v1")).rejects.toThrow(
          /Invalid response from HPKE key endpoint/
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("rejects failed key fetch", async () => {
      const fetchMock = vi.fn(async () => {
        return new Response(null, {
          status: 500,
          statusText: "Internal Server Error",
        });
      });

      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchMock as typeof fetch;

      try {
        await expect(getServerIdentity("https://example.com/v1")).rejects.toThrow(
          /Failed to fetch HPKE public key from enclave/
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("successfully retrieves server identity with valid response", async () => {
      const mockIdentity = await Identity.generate();
      const publicConfig = await mockIdentity.marshalConfig();

      const fetchMock = vi.fn(async (url: string) => {
        expect(url).toBe("https://example.com/.well-known/hpke-keys");
        return new Response(publicConfig as unknown as BodyInit, {
          status: 200,
          headers: { "content-type": PROTOCOL.KEYS_MEDIA_TYPE },
        });
      });

      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchMock as typeof fetch;

      try {
        const identity = await getServerIdentity("https://example.com/v1");
        expect(identity).toBeInstanceOf(Identity);
        expect(fetchMock).toHaveBeenCalledTimes(1);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("normalizeEncryptedBodyRequestArgs", () => {
    it("handles string URLs", () => {
      const result = normalizeEncryptedBodyRequestArgs("https://example.com/test");
      expect(result.url).toBe("https://example.com/test");
      expect(result.init).toBeUndefined();
    });

    it("handles URL objects", () => {
      const url = new URL("https://example.com/test");
      const result = normalizeEncryptedBodyRequestArgs(url);
      expect(result.url).toBe("https://example.com/test");
      expect(result.init).toBeUndefined();
    });

    it("handles Request objects", () => {
      const request = new Request("https://example.com/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test: "data" }),
      });

      const result = normalizeEncryptedBodyRequestArgs(request);
      expect(result.url).toBe("https://example.com/test");
      expect(result.init?.method).toBe("POST");
      expect(result.init?.headers).toBeInstanceOf(Headers);
    });

    it("merges init options with Request", () => {
      const request = new Request("https://example.com/test", {
        method: "POST",
      });

      const result = normalizeEncryptedBodyRequestArgs(request, {
        headers: { "X-Custom": "header" },
      });

      expect(result.url).toBe("https://example.com/test");
      expect(result.init?.headers).toBeTruthy();
    });

    it("handles string URLs with init options", () => {
      const result = normalizeEncryptedBodyRequestArgs("https://example.com/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      expect(result.url).toBe("https://example.com/test");
      expect(result.init?.method).toBe("POST");
    });
  });

  describe("encryptedBodyRequest", () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
      originalFetch = globalThis.fetch;
    });

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it("makes request with valid HPKE key", async () => {
      const serverIdentity = await Identity.generate();
      const keyHex = await serverIdentity.getPublicKeyHex();

      let apiRequestMade = false;
      globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (url.includes("api.example.com")) {
          apiRequestMade = true;
        }
        return new Response("ok");
      }) as typeof fetch;

      await encryptedBodyRequest(
        "https://api.example.com/test",
        keyHex
      );

      expect(apiRequestMade).toBe(true);
    });
  });

  describe("createEncryptedBodyFetch", () => {
    it("resolves absolute path URLs against baseURL origin", () => {
      const normalized = normalizeEncryptedBodyRequestArgs("/users");
      const targetUrl = new URL(normalized.url, "https://api.example.com/v1");
      expect(targetUrl.toString()).toBe("https://api.example.com/users");
    });

    it("resolves relative URLs against baseURL", () => {
      const normalized = normalizeEncryptedBodyRequestArgs("users");
      const targetUrl = new URL(normalized.url, "https://api.example.com/v1/");
      expect(targetUrl.toString()).toBe("https://api.example.com/v1/users");
    });

    it("handles absolute URLs correctly", () => {
      const normalized = normalizeEncryptedBodyRequestArgs("https://other.example.com/endpoint");
      const targetUrl = new URL(normalized.url, "https://api.example.com/v1");
      expect(targetUrl.toString()).toBe("https://other.example.com/endpoint");
    });

    it("returns a function with fetch signature", () => {
      const customFetch = createEncryptedBodyFetch("https://api.example.com", "mockkey123");
      expect(typeof customFetch).toBe("function");
      expect(customFetch.length).toBe(2);
    });

  });

  describe("createUnverifiedEncryptedBodyFetch", () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
      originalFetch = globalThis.fetch;
    });

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it("fetches HPKE key from server", async () => {
      const serverIdentity = await Identity.generate();
      const publicConfig = await serverIdentity.marshalConfig();

      let keyFetched = false;
      let apiRequestMade = false;

      globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (url.includes("/.well-known/hpke-keys")) {
          keyFetched = true;
          return new Response(publicConfig as unknown as BodyInit, {
            status: 200,
            headers: { "content-type": PROTOCOL.KEYS_MEDIA_TYPE },
          });
        }
        if (url.includes("api.example.com")) {
          apiRequestMade = true;
        }
        return new Response("ok");
      }) as typeof fetch;

      const unverifiedFetch = createUnverifiedEncryptedBodyFetch("https://api.example.com");
      await unverifiedFetch("/test");

      expect(keyFetched).toBe(true);
      expect(apiRequestMade).toBe(true);
    });

    it("fetches HPKE key from keyOrigin when provided", async () => {
      const serverIdentity = await Identity.generate();
      const publicConfig = await serverIdentity.marshalConfig();

      let keyFetchedFromEnclave = false;

      globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (url.includes("enclave.example.com") && url.includes("/.well-known/hpke-keys")) {
          keyFetchedFromEnclave = true;
          return new Response(publicConfig as unknown as BodyInit, {
            status: 200,
            headers: { "content-type": PROTOCOL.KEYS_MEDIA_TYPE },
          });
        }
        return new Response("ok");
      }) as typeof fetch;

      const unverifiedFetch = createUnverifiedEncryptedBodyFetch(
        "https://api.example.com",
        "https://enclave.example.com"
      );
      await unverifiedFetch("/test");

      expect(keyFetchedFromEnclave).toBe(true);
    });

    it("returns a function with fetch signature", () => {
      const customFetch = createUnverifiedEncryptedBodyFetch("https://api.example.com");
      expect(typeof customFetch).toBe("function");
      expect(customFetch.length).toBe(2);
    });
  });
});
