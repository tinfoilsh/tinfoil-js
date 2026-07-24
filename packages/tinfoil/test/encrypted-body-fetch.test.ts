import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { encryptedBodyRequest, normalizeEncryptedBodyRequestArgs, getServerIdentity, createEncryptedBodyFetch, createUnverifiedEncryptedBodyFetch } from "../src/encrypted-body-fetch";
import { Identity, KeyConfigMismatchError, PROTOCOL } from "ehbp";

describe("encrypted-body-fetch", () => {
  describe("getServerIdentity", () => {
    it("retrieves keys from a non-HTTPS URL", async () => {
      const mockIdentity = await Identity.generate();
      const publicConfig = await mockIdentity.marshalConfig();
      const fetchMock = vi.fn(async () => new Response(publicConfig as unknown as BodyInit, {
        status: 200,
        headers: { "content-type": PROTOCOL.KEYS_MEDIA_TYPE },
      }));

      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchMock as typeof fetch;

      try {
        await expect(getServerIdentity("http://localhost:3000/v1")).resolves.toBeInstanceOf(Identity);
        expect(fetchMock).toHaveBeenCalledWith("http://localhost:3000/.well-known/hpke-keys");
      } finally {
        globalThis.fetch = originalFetch;
      }
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
        credentials: "include",
        redirect: "manual",
      });

      const result = normalizeEncryptedBodyRequestArgs(request, {
        headers: { "X-Custom": "header" },
        credentials: "omit",
      });

      expect(result.url).toBe("https://example.com/test");
      expect(result.init?.headers).toBeTruthy();
      expect(result.init?.credentials).toBe("omit");
      expect(result.init?.redirect).toBe("manual");
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

    function capturingTransport() {
      const request = vi.fn(async () => new Response(null));
      return {
        request,
        transport: { request } as unknown as import("ehbp").Transport,
      };
    }

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

    it("passes through nonce-less errors after encrypted requests", async () => {
      const serverIdentity = await Identity.generate();
      const keyHex = await serverIdentity.getPublicKeyHex();
      globalThis.fetch = vi.fn(async () => new Response("proxy rejected request", {
        status: 502,
        headers: {
          "Content-Type": "text/plain",
          "X-Proxy": "edge",
        },
      })) as typeof fetch;

      const response = await encryptedBodyRequest(
        "https://api.example.com/test",
        keyHex,
        { method: "POST", body: "secret" },
      );

      expect(response.status).toBe(502);
      expect(response.headers.get("x-proxy")).toBe("edge");
      await expect(response.text()).resolves.toBe("proxy rejected request");
    });

    it("inherits a Request body when init explicitly sets body to null", async () => {
      const { request: requestSpy, transport } = capturingTransport();
      const request = new Request("https://api.example.com/test", {
        method: "POST",
        body: "inherited body",
      });

      await encryptedBodyRequest(
        request,
        "",
        { body: null },
        transport,
      );

      const sentBody = requestSpy.mock.calls[0][1]!.body as BodyInit;
      await expect(new Response(sentBody).text()).resolves.toBe("inherited body");
    });

    it("retains EHBP key mismatch errors", async () => {
      const serverIdentity = await Identity.generate();
      const keyHex = await serverIdentity.getPublicKeyHex();
      globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({
        type: PROTOCOL.KEY_CONFIG_PROBLEM_TYPE,
        title: "stale key",
      }), {
        status: 422,
        headers: { "Content-Type": PROTOCOL.PROBLEM_JSON_MEDIA_TYPE },
      })) as typeof fetch;

      await expect(encryptedBodyRequest(
        "https://api.example.com/test",
        keyHex,
        { method: "POST", body: "secret" },
      )).rejects.toBeInstanceOf(KeyConfigMismatchError);
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

    it("returns a SecureTransport object", () => {
      const transport = createEncryptedBodyFetch("https://api.example.com", "mockkey123");
      expect(typeof transport).toBe("object");
      expect(typeof transport.fetch).toBe("function");
      expect(typeof transport.getSessionRecoveryToken).toBe("function");
    });

    it("allows a non-HTTPS baseURL", () => {
      expect(() => createEncryptedBodyFetch("http://api.example.com", "mockkey123")).not.toThrow();
    });

    it("refuses requests to an origin outside the enclave/proxy", async () => {
      const transport = createEncryptedBodyFetch("https://api.example.com", "mockkey123");
      await expect(transport.fetch("https://evil.example.com/steal")).rejects.toThrow(
        /refusing to send request/
      );
    });

    it("allows requests to the baseURL origin", async () => {
      const serverIdentity = await Identity.generate();
      const keyHex = await serverIdentity.getPublicKeyHex();

      let apiRequestMade = false;
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (url.includes("api.example.com")) apiRequestMade = true;
        return new Response("ok");
      }) as typeof fetch;

      try {
        const transport = createEncryptedBodyFetch("https://api.example.com", keyHex);
        await transport.fetch("/test");
        expect(apiRequestMade).toBe(true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("allows requests to the enclave origin when routing through a proxy", async () => {
      const serverIdentity = await Identity.generate();
      const keyHex = await serverIdentity.getPublicKeyHex();

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn(async () => new Response("ok")) as typeof fetch;

      try {
        const transport = createEncryptedBodyFetch(
          "https://proxy.example.com",
          keyHex,
          "https://enclave.example.com"
        );
        await expect(
          transport.fetch("https://enclave.example.com/test")
        ).resolves.toBeInstanceOf(Response);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("preserves Request options and applies native init precedence", async () => {
      const serverIdentity = await Identity.generate();
      const keyHex = await serverIdentity.getPublicKeyHex();
      const originalFetch = globalThis.fetch;
      let sentRequest: Request | undefined;
      globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
        sentRequest = input as Request;
        return new Response("rejected", { status: 503 });
      }) as typeof fetch;

      try {
        const request = new Request("https://api.example.com/test", {
          method: "POST",
          headers: { "X-Source": "request" },
          body: "secret",
          cache: "no-store",
          credentials: "include",
          integrity: "sha256-request",
          keepalive: true,
          mode: "cors",
          redirect: "manual",
          referrer: "https://referrer.example.com/source",
          referrerPolicy: "origin",
        });
        const signal = new AbortController().signal;
        const transport = createEncryptedBodyFetch("https://api.example.com", keyHex);

        const response = await transport.fetch(request, {
          method: "PUT",
          headers: { "X-Source": "init" },
          cache: "reload",
          credentials: "omit",
          integrity: "sha256-init",
          keepalive: false,
          mode: "same-origin",
          redirect: "error",
          referrer: "",
          referrerPolicy: "no-referrer",
          signal,
        });

        expect(response.status).toBe(503);
        expect(sentRequest).toBeInstanceOf(Request);
        expect(sentRequest?.method).toBe("PUT");
        expect(sentRequest?.headers.get("x-source")).toBe("init");
        expect(sentRequest?.cache).toBe("reload");
        expect(sentRequest?.credentials).toBe("omit");
        expect(sentRequest?.integrity).toBe("sha256-init");
        expect(sentRequest?.keepalive).toBe(false);
        expect(sentRequest?.mode).toBe("same-origin");
        expect(sentRequest?.redirect).toBe("error");
        expect(sentRequest?.referrer).toBe("");
        expect(sentRequest?.referrerPolicy).toBe("no-referrer");
        expect(sentRequest?.signal.aborted).toBe(false);
      } finally {
        globalThis.fetch = originalFetch;
      }
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

      const transport = createUnverifiedEncryptedBodyFetch("http://api.example.com");
      await transport.fetch("/test");

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

      const transport = createUnverifiedEncryptedBodyFetch(
        "https://api.example.com",
        "https://enclave.example.com"
      );
      await transport.fetch("/test");

      expect(keyFetchedFromEnclave).toBe(true);
    });

    it("returns a SecureTransport object", () => {
      const transport = createUnverifiedEncryptedBodyFetch("https://api.example.com");
      expect(typeof transport).toBe("object");
      expect(typeof transport.fetch).toBe("function");
      expect(typeof transport.getSessionRecoveryToken).toBe("function");
    });
  });
});
