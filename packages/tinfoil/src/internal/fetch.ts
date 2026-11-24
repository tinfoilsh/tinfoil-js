/**
 * Retrieves raw attestation documents from enclaves. Nothing is parsed here;
 * verification belongs to the verifier.
 */
import { NONCE_SIZE, toHex } from "@tinfoilsh/verifier";
import { SDK_NAME, SDK_VERSION } from "../version.js";
import { ConfigurationError, messageOf, NetworkError, TinfoilError } from "../errors.js";
import type { AttestationFetcher, Fetch } from "../options.js";

export const ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation";
export const SDK_NAME_HEADER = "Tinfoil-SDK";
export const SDK_VERSION_HEADER = "Tinfoil-SDK-Version";
export const ATTESTATION_FETCH_TIMEOUT_MS = 30_000;
export const MAX_ATTESTATION_BYTES = 32 << 20;
const MAX_REDIRECTS = 10;

/**
 * Where the attestation document of `host`, a host with an optional port, is
 * fetched with `nonce`: from the host itself.
 */
export function attestationURL(host: string, nonce: Uint8Array): string {
  if (host === "") throw new ConfigurationError("enclave host is required");
  if (nonce.length !== NONCE_SIZE) throw new ConfigurationError(`nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  if (!isAuthority(host)) throw new ConfigurationError(`invalid host ${JSON.stringify(host)}: want a host with an optional port`);
  return `https://${host}${ATTESTATION_ENDPOINT}?nonce=${toHex(nonce)}`;
}

/**
 * GET the attestation document with the SDK headers, following at most ten
 * HTTPS redirects, within 30 seconds, capped at 32 MiB while the body
 * streams. A bad host or nonce is a {@link ConfigurationError}; everything
 * else that fails is a {@link NetworkError}. `signal` ends the fetch early;
 * the timeout applies either way.
 */
export async function fetchDocument(host: string, nonce: Uint8Array, fetchImpl: Fetch = fetch, signal?: AbortSignal): Promise<Uint8Array> {
  return fetchDocumentAt(attestationURL(host, nonce), fetchImpl, signal);
}

/**
 * GET the attestation document at `target` under the bounds of a direct
 * fetch; anything that fails is a {@link NetworkError}, unless it already is
 * an SDK error.
 */
async function fetchDocumentAt(target: string, fetchImpl: Fetch, signal: AbortSignal | undefined): Promise<Uint8Array> {
  try {
    const response = await getFollowingRedirects(target, fetchImpl, signal);
    if (response.status > 299) {
      await response.body?.cancel();
      throw new Error(`HTTP GET ${target}: ${response.status} ${response.statusText}`);
    }
    return await readBounded(response, MAX_ATTESTATION_BYTES, "attestation document");
  } catch (err) {
    if (err instanceof TinfoilError) throw err;
    throw new NetworkError(messageOf(err), { cause: err });
  }
}

/**
 * GET the attestation document of `host` for `nonce` through the relay at
 * `relayURL`, a validated base URL ending with `/`, under the bounds of a
 * direct fetch. A bad host or nonce is a {@link ConfigurationError};
 * everything else that fails is a {@link NetworkError}.
 */
export async function fetchRelayedDocument(relayURL: string, host: string, nonce: Uint8Array, fetchImpl: Fetch, signal?: AbortSignal): Promise<Uint8Array> {
  attestationURL(host, nonce);
  const target = `${relayURL.replace(/\/$/, "")}${ATTESTATION_ENDPOINT}?nonce=${toHex(nonce)}&enclave=${encodeURIComponent(host)}`;
  return fetchDocumentAt(target, fetchImpl, signal);
}

/**
 * The document that a caller's fetcher returns for `host` and `nonce`. The
 * fetcher gets its own copy of the nonce and a signal that ends after the
 * fetch timeout, or when `signal` does; a verification that several callers
 * share passes no `signal`, so that one caller's cancellation doesn't end it.
 * The wait ends with the fetcher's signal, even if the fetcher ignores it. A fetcher's error is a
 * {@link NetworkError} that wraps it unless it already is an SDK error; a
 * result that isn't a `Uint8Array` is a {@link ConfigurationError}, and one
 * over the size limit a {@link NetworkError}.
 */
export async function fetchDocumentWith(fetcher: AttestationFetcher, host: string, nonce: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
  const timeout = AbortSignal.timeout(ATTESTATION_FETCH_TIMEOUT_MS);
  const combined = signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
  let doc: unknown;
  try {
    doc = await untilAborted(Promise.resolve().then(() => fetcher(host, nonce.slice(), { signal: combined })), combined);
  } catch (err) {
    if (err instanceof TinfoilError) throw err;
    throw new NetworkError(`fetching the attestation document of ${host}: ${messageOf(err)}`, { cause: err });
  }
  if (!(doc instanceof Uint8Array)) throw new ConfigurationError("fetchAttestation must resolve to a Uint8Array");
  if (doc.length > MAX_ATTESTATION_BYTES) throw new NetworkError(`attestation document exceeds ${MAX_ATTESTATION_BYTES} bytes`);
  return doc;
}

/** `promise`, or a rejection with `signal`'s reason as soon as it aborts. */
export function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (err: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(err);
      },
    );
  });
}

/** GET `url` with the SDK headers, following at most ten HTTPS redirects, within `timeoutMs` or until `signal` aborts. */
export async function getFollowingRedirects(url: string, fetchImpl: Fetch, signal: AbortSignal | undefined, timeoutMs: number = ATTESTATION_FETCH_TIMEOUT_MS): Promise<Response> {
  const timeout = AbortSignal.timeout(timeoutMs);
  const combined = signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
  let target = url;
  for (let hops = 0; ; hops++) {
    const response = await fetchImpl(target, {
      method: "GET",
      redirect: "manual",
      headers: { [SDK_NAME_HEADER]: SDK_NAME, [SDK_VERSION_HEADER]: SDK_VERSION },
      signal: combined,
    });
    // A runtime that hides redirects (a browser) answers with an opaque
    // response; the document can't be fetched through a redirect there.
    if (response.type === "opaqueredirect") throw new Error(`HTTP GET ${target}: redirected, which this runtime does not follow`);
    if (response.status < 300 || response.status > 399) return response;
    await response.body?.cancel();
    const location = response.headers.get("location");
    if (location === null) throw new Error(`HTTP GET ${target}: ${response.status} without a Location header`);
    const next = new URL(location, target);
    if (next.protocol !== "https:") throw new Error(`refusing redirect to non-HTTPS URL ${next.href}`);
    if (hops >= MAX_REDIRECTS) throw new Error(`stopped after ${MAX_REDIRECTS} redirects`);
    target = next.href;
  }
}

/** Reads the body, stopping as soon as it exceeds `limit` bytes. */
export async function readBounded(response: Response, limit: number, what: string): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new Error(`${what} exceeds ${limit} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** The host name (IPv6 without brackets) and port an authority names. */
export function endpointOf(authority: string): { hostname: string; port: number } | undefined {
  let u: URL;
  try {
    u = new URL(`https://${authority}`);
  } catch {
    return undefined;
  }
  // A URL drops the default port and lowercases the host, so rebuild the
  // authority to compare it, case-insensitively, with what was given.
  const port = u.port === "" ? 443 : Number(u.port);
  const rebuilt = u.port === "" ? (authority.endsWith(":443") ? `${u.hostname}:443` : u.hostname) : `${u.hostname}:${u.port}`;
  if (rebuilt !== authority.toLowerCase() || u.pathname !== "/" || u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "") {
    return undefined;
  }
  const hostname = u.hostname.startsWith("[") && u.hostname.endsWith("]") ? u.hostname.slice(1, -1) : u.hostname;
  return { hostname, port };
}

/** Whether `s` is exactly the host (with optional port) of an HTTPS URL. */
export function isAuthority(s: string): boolean {
  return endpointOf(s) !== undefined;
}
