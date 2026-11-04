/**
 * The TLS transport mode: every connection is pinned to the attested TLS
 * key, so the whole request and response are protected, and a plaintext
 * request is refused because no pinned connection carries it. The pin is
 * checked in the TLS handshake, after the normal certificate check, on
 * every connection; a peer whose certificate doesn't carry the key never
 * receives the request. Node makes the connections through its HTTPS
 * client, so request and response bodies stream through; Bun checks the
 * pin through its fetch's TLS options. This module is for Node and Bun
 * only; the browser entry maps it to a stub.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { isBun } from "../../../env.js";
import { AttestationError, ConfigurationError, messageOf, NetworkError } from "../../errors.js";
import type { Fetch } from "../../options.js";
import { CERT_MISMATCH, isCertificateError } from "./pin-errors.js";
import { identityCheck } from "./pin.js";
import { PeerLacksKeyError, type BoundFetch, type Mode } from "./transport.js";

/** Settings of the normal certificate check, which runs before the pin and can only reject. */
export interface TLSOptions {
  /** Certificate authorities to trust instead of the runtime's bundle. */
  readonly ca?: string | Uint8Array;
}

/** A mode that pins each connection's leaf certificate to the TLS key the current verification attests. */
export function tlsMode(options: TLSOptions = {}): Mode {
  return {
    name: "tls",
    validateRequest(request) {
      if (request.url.protocol !== "https:") throw new ConfigurationError("TLS transport mode requires an HTTPS request");
    },
    async bind(v: Verification) {
      const key = v.tlsPublicKeyFP();
      if (key === undefined) throw new AttestationError('document endorses no "tls" key');
      return isBun() ? bunPinnedFetch(key, options) : nodePinnedFetch(key, options);
    },
  };
}

/** The error a failed request surfaces as: a certificate failure means the peer lacks the key; anything else is a network error. */
function classify(err: unknown): Error {
  if (err instanceof PeerLacksKeyError) return err;
  if (isCertificateError(err)) return new PeerLacksKeyError(messageOf(err), { cause: err });
  if (err instanceof Error && err.name === "AbortError") return err;
  return new NetworkError(messageOf(err), { cause: err });
}

// ---------------------------------------------------------------- Node

async function nodePinnedFetch(key: string, options: TLSOptions): Promise<BoundFetch> {
  const [https, { Readable }, checkServerIdentity] = await Promise.all([import("node:https"), import("node:stream"), identityCheck(key)]);
  type IncomingMessage = import("node:http").IncomingMessage;

  const agent = new https.Agent({ keepAlive: true });
  // An idle pooled connection must not keep the process alive; a reused one is referenced again.
  agent.on("free", (socket: import("node:net").Socket) => socket.unref());
  const ca = options.ca === undefined ? undefined : typeof options.ca === "string" ? options.ca : Buffer.from(options.ca);

  const fetchImpl: Fetch = async (input, init) => {
    const request = input instanceof Request ? input : undefined;
    const url = new URL(request?.url ?? String(input));
    if (url.protocol !== "https:") throw new ConfigurationError("TLS transport mode requires an HTTPS request");
    const method = (init?.method ?? request?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers ?? request?.headers);
    const body = await requestBody(init?.body ?? request, headers);
    const signal = init?.signal ?? request?.signal;
    signal?.throwIfAborted();

    const res = await new Promise<IncomingMessage>((resolve, reject) => {
      const req = https.request(
        {
          protocol: url.protocol,
          hostname: url.hostname.replace(/^\[|\]$/g, ""),
          port: url.port === "" ? 443 : Number(url.port),
          path: `${url.pathname}${url.search}`,
          method,
          headers: Object.fromEntries(headers.entries()),
          agent,
          ca,
          servername: url.hostname.replace(/^\[|\]$/g, ""),
          checkServerIdentity,
        },
        resolve,
      );
      req.once("error", (err) => reject(classify(err)));
      if (signal !== undefined) {
        const onAbort = (): void => {
          req.destroy(signal.reason instanceof Error ? signal.reason : new Error(String(signal.reason)));
          reject(signal.reason);
        };
        signal.addEventListener("abort", onAbort, { once: true });
        req.once("close", () => signal.removeEventListener("abort", onAbort));
      }
      if (body === undefined) {
        req.end();
      } else if (body instanceof ReadableStream) {
        Readable.fromWeb(body as unknown as import("node:stream/web").ReadableStream)
          .once("error", (err) => req.destroy(err))
          .pipe(req);
      } else {
        req.end(body);
      }
    });

    const responseHeaders = new Headers();
    for (const [name, value] of Object.entries(res.headers)) {
      if (Array.isArray(value)) for (const v of value) responseHeaders.append(name, v);
      else if (value !== undefined) responseHeaders.set(name, value);
    }
    const status = res.statusCode ?? 0;
    const bodiless = method === "HEAD" || status === 204 || status === 304;
    if (bodiless) res.resume();
    return new Response(bodiless ? null : (Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>), {
      status,
      statusText: res.statusMessage ?? "",
      headers: responseHeaders,
    });
  };

  return { fetch: fetchImpl, close: () => agent.destroy() };
}

/**
 * The bytes or stream to send, with the body's content type added to
 * `headers` when the caller set none. A stream streams; everything else is
 * read into memory first, as fetch does.
 */
async function requestBody(body: BodyInit | Request | null | undefined, headers: Headers): Promise<Uint8Array | string | ReadableStream<Uint8Array> | undefined> {
  if (body === null || body === undefined) return undefined;
  if (body instanceof Request) {
    if (body.body === null) return undefined;
    return body.body;
  }
  if (typeof body === "string") return body;
  if (body instanceof ReadableStream) return body as ReadableStream<Uint8Array>;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  // Blob, FormData and URLSearchParams: let the platform encode them and name their content type.
  const encoded = new Response(body);
  const contentType = encoded.headers.get("content-type");
  if (contentType !== null && !headers.has("content-type")) headers.set("content-type", contentType);
  return new Uint8Array(await encoded.arrayBuffer());
}

// ---------------------------------------------------------------- Bun

async function bunPinnedFetch(key: string, options: TLSOptions): Promise<BoundFetch> {
  const checkServerIdentity = await identityCheck(key);
  const fetchImpl: Fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.protocol !== "https:") throw new ConfigurationError("TLS transport mode requires an HTTPS request");
    try {
      // `tls` is the runtime's own fetch option for the connection's TLS settings.
      return await fetch(input, { ...init, tls: { ca: options.ca, checkServerIdentity } } as RequestInit);
    } catch (err) {
      if (messageOf(err).includes(CERT_MISMATCH)) throw new PeerLacksKeyError(CERT_MISMATCH, { cause: err });
      throw classify(err);
    }
  };
  return { fetch: fetchImpl };
}
