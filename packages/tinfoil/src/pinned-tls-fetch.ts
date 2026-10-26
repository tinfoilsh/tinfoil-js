import { X509Certificate, createHash } from "crypto";
import { ConfigurationError, bindingError } from "./errors.js";
import { isBun } from "./env.js";
import { httpURL } from "./acquisition.js";
import { boundRedirectFetch } from "./redirects.js";

export function createCheckServerIdentity(expectedFingerprintHex: string): (host: string, cert: { raw?: Buffer }) => Error | undefined {
  if (!/^[0-9a-f]{64}$/.test(expectedFingerprintHex)) throw new ConfigurationError("TLS fingerprint must contain 32 lowercase hexadecimal bytes");
  return (_host, cert) => {
    if (!cert?.raw) return bindingError("TLS peer certificate is unavailable");
    const certificate = new X509Certificate(cert.raw);
    const fingerprint = createHash("sha256").update(certificate.publicKey.export({ type: "spki", format: "der" })).digest("hex");
    return fingerprint === expectedFingerprintHex ? undefined : bindingError("TLS peer public key does not match the attested key");
  };
}
export async function createPinnedTlsFetch(baseURL: string, expectedFingerprintHex: string): Promise<typeof fetch> {
  const base = httpURL(baseURL, "TLS baseURL", true);
  const tls = await import("tls");
  const check = createCheckServerIdentity(expectedFingerprintHex);
  const checkServerIdentity = (host: string, cert: import("tls").PeerCertificate) => check(host, cert) ?? tls.checkServerIdentity(host, cert);
  const send = isBun()
    ? async (request: Request): Promise<Response> => globalThis.fetch(request, { tls: { checkServerIdentity, rejectUnauthorized: true } } as RequestInit)
    : await nodeSender(checkServerIdentity);
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input), base);
    if (url.origin !== base.origin || url.username || url.password) throw new ConfigurationError("TLS request must target the verified HTTPS origin");
    const request = new Request(input instanceof Request ? input : url, init);
    request.signal.throwIfAborted();
    return boundRedirectFetch(request, send);
  }) as typeof fetch;
}
async function nodeSender(checkServerIdentity: (host: string, cert: import("tls").PeerCertificate) => Error | undefined): Promise<(request: Request) => Promise<Response>> {
  const https = await import("https");
  const { Readable } = await import("stream");
  return async request => {
    const url = new URL(request.url);
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => { headers[key] = value; });
    const incoming = await new Promise<import("http").IncomingMessage>((resolve, reject) => {
      const req = https.request(url, { method: request.method, headers, checkServerIdentity, rejectUnauthorized: true, agent: false }, resolve);
      const abort = () => req.destroy(request.signal.reason instanceof Error ? request.signal.reason : new DOMException("Request aborted", "AbortError"));
      req.once("error", reject);
      req.once("close", () => request.signal.removeEventListener("abort", abort));
      request.signal.addEventListener("abort", abort, { once: true });
      if (request.signal.aborted) { abort(); return; }
      if (request.body) {
        const body = Readable.fromWeb(request.body as import("stream/web").ReadableStream);
        body.once("error", error => req.destroy(error));
        req.once("error", () => body.destroy());
        body.pipe(req);
      } else req.end();
    });
    const responseHeaders = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (Array.isArray(value)) value.forEach(entry => responseHeaders.append(name, entry));
      else if (value !== undefined) responseHeaders.set(name, value);
    }
    const status = incoming.statusCode!;
    const noBody = request.method === "HEAD" || [204, 205, 304].includes(status);
    if (noBody) incoming.resume();
    const response = new Response(noBody ? null : Readable.toWeb(incoming) as ReadableStream, { status, statusText: incoming.statusMessage, headers: responseHeaders });
    Object.defineProperty(response, "url", { value: request.url });
    return response;
  };
}
