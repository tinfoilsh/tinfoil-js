import { X509Certificate, createHash } from "crypto";
import type { ReadableStream as NodeWebReadableStream } from "stream/web";
import { ConfigurationError, AttestationError } from "./verifier.js";

function isBun(): boolean {
  return typeof process !== "undefined" &&
    (process as any).versions &&
    (process as any).versions.bun;
}

function createCheckServerIdentity(expectedFingerprintHex: string): (host: string, cert: any) => Error | undefined {
  return (host: string, cert: any): Error | undefined => {
    const raw = cert?.raw as Buffer | undefined;
    if (!raw) {
      return new AttestationError("Certificate raw bytes are unavailable for pinning");
    }
    const x509 = new X509Certificate(raw);
    const publicKeyDer = x509.publicKey.export({ type: "spki", format: "der" });
    const fp = createHash("sha256").update(publicKeyDer).digest("hex");
    if (fp !== expectedFingerprintHex) {
      return new AttestationError(`Certificate public key fingerprint mismatch. Expected: ${expectedFingerprintHex}, Got: ${fp}`);
    }
    return undefined;
  };
}

async function createBunPinnedTlsFetch(baseURL: string, expectedFingerprintHex: string): Promise<typeof fetch> {
  const tls = await import("tls");
  const fingerprintCheck = createCheckServerIdentity(expectedFingerprintHex);

  const parsedBase = new URL(baseURL);
  if (parsedBase.protocol !== "https:") {
    throw new ConfigurationError(`HTTP connections are not allowed. Use HTTPS. URL: ${baseURL}`);
  }

  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const makeURL = (value: RequestInfo | URL): URL => {
      if (typeof value === "string") return new URL(value, baseURL);
      if (value instanceof URL) return value;
      return new URL((value as Request).url, baseURL);
    };

    const url = makeURL(input);
    if (url.protocol !== "https:") {
      throw new ConfigurationError(`HTTP connections are not allowed. Use HTTPS. URL: ${url.toString()}`);
    }

    const fetchInit: RequestInit & { tls?: { checkServerIdentity: (host: string, cert: any) => Error | undefined } } = {
      ...init,
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore - Bun-specific option
      tls: {
        checkServerIdentity: (host: string, cert: any) => {
          const result = fingerprintCheck(host, cert);
          if (result) return result;
          return tls.checkServerIdentity(host, cert);
        },
      },
    };

    return fetch(url.toString(), fetchInit);
  }) as typeof fetch;
}

async function createNodePinnedTlsFetch(baseURL: string, expectedFingerprintHex: string): Promise<typeof fetch> {
  const https = await import("https");
  const tls = await import("tls");
  const { Readable } = await import("stream");

  const checkServerIdentity = createCheckServerIdentity(expectedFingerprintHex);

  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    // Normalize URL with base URL support
    const makeURL = (value: RequestInfo | URL): URL => {
      if (typeof value === "string") return new URL(value, baseURL);
      if (value instanceof URL) return value;
      return new URL((value as Request).url, baseURL);
    };

    const url = makeURL(input);
    if (url.protocol !== "https:") {
      throw new ConfigurationError(`HTTP connections are not allowed. Use HTTPS. URL: ${url.toString()}`);
    }

    // Gather method and headers
    const method = (init?.method || (input as any).method || "GET").toUpperCase();
    const headers = new Headers(init?.headers || (input as any)?.headers || {});
    const headerObj: Record<string, string> = {};
    headers.forEach((v, k) => {
      headerObj[k] = v;
    });

    // Resolve body
    let body: any = init?.body;
    if (!body && input instanceof Request) {
      // If the original was a Request with a body, read it
      try {
        const buf = await (input as Request).arrayBuffer();
        if (buf && (buf as ArrayBuffer).byteLength) body = Buffer.from(buf as ArrayBuffer);
      } catch {}
    }
    // Convert web streams to Node streams if needed
    if (body && typeof (body as any).getReader === "function") {
      body = Readable.fromWeb(body as unknown as NodeWebReadableStream);
    }
    if (body instanceof ArrayBuffer) {
      body = Buffer.from(body);
    }
    if (ArrayBuffer.isView(body)) {
      body = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
    }

    const requestOptions: import("https").RequestOptions & import("tls").ConnectionOptions = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port ? Number(url.port) : 443,
      path: `${url.pathname}${url.search}`,
      method,
      headers: headerObj,
      checkServerIdentity: (host, cert) => {
        const result = checkServerIdentity(host, cert);
        if (result) return result;
        return tls.checkServerIdentity(host, cert);
      },
    };

    const { signal } = init || {};

    const res = await new Promise<import("http").IncomingMessage>((resolve, reject) => {
      const req = https.request(requestOptions, resolve);
      req.on("error", reject);
      if (signal) {
        if ((signal as AbortSignal).aborted) {
          req.destroy(new Error("Request aborted"));
          return;
        }
        (signal as AbortSignal).addEventListener("abort", () => req.destroy(new Error("Request aborted")));
      }
      if (body === undefined || body === null) {
        req.end();
      } else if (typeof body === "string" || Buffer.isBuffer(body) || ArrayBuffer.isView(body)) {
        req.end(body as any);
      } else if (typeof (body as any).pipe === "function") {
        (body as any).pipe(req);
      } else {
        // Fallback: try to serialize objects
        req.end(String(body));
      }
    });

    const responseHeaders = new Headers();
    for (const [k, v] of Object.entries(res.headers)) {
      if (Array.isArray(v)) {
        v.forEach(item => responseHeaders.append(k, item));
      } else if (v != null) {
        responseHeaders.set(k, String(v));
      }
    }

    // Convert Node stream to Web ReadableStream
    const webStream = Readable.toWeb(res as unknown as import("stream").Readable) as unknown as ReadableStream;
    return new Response(webStream, {
      status: res.statusCode || 0,
      statusText: res.statusMessage || "",
      headers: responseHeaders,
    });
  }) as typeof fetch;
}

export async function createPinnedTlsFetch(baseURL: string, expectedFingerprintHex: string): Promise<typeof fetch> {
  if (isBun()) {
    return createBunPinnedTlsFetch(baseURL, expectedFingerprintHex);
  }
  return createNodePinnedTlsFetch(baseURL, expectedFingerprintHex);
}