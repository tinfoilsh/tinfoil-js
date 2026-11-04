/**
 * Retrieves raw attestation documents from enclaves. Nothing is parsed here;
 * verification belongs to the verifier.
 */
import { NONCE_SIZE } from "@tinfoilsh/verifier/v3";
import { SDK_NAME, SDK_VERSION } from "../../version.js";
import { ConfigurationError, messageOf, NetworkError, TinfoilError } from "../errors.js";
import type { Fetch } from "../options.js";

export const ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation";
export const SDK_NAME_HEADER = "Tinfoil-SDK";
export const SDK_VERSION_HEADER = "Tinfoil-SDK-Version";
export const ATTESTATION_FETCH_TIMEOUT_MS = 30_000;
export const MAX_ATTESTATION_BYTES = 32 << 20;
const MAX_REDIRECTS = 10;

/**
 * Where the attestation document of `host` is fetched with `nonce`: from the
 * host itself, or from `relay`, which forwards the request to the host, when
 * a relay is given. Both are a host with an optional port, not a URL.
 */
export function attestationURL(host: string, relay: string | undefined, nonce: Uint8Array): string {
  if (host === "") throw new ConfigurationError("enclave host is required");
  if (nonce.length !== NONCE_SIZE) throw new ConfigurationError(`nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  for (const authority of [host, relay]) {
    if (authority !== undefined && authority !== "" && !isAuthority(authority)) {
      throw new ConfigurationError(`invalid host ${JSON.stringify(authority)}: want a host with an optional port`);
    }
  }
  const hex = Array.from(nonce, (b) => b.toString(16).padStart(2, "0")).join("");
  if (relay === undefined || relay === "") return `https://${host}${ATTESTATION_ENDPOINT}?nonce=${hex}`;
  return `https://${relay}${ATTESTATION_ENDPOINT}?nonce=${hex}&enclave=${encodeURIComponent(host)}`;
}

/**
 * GET the attestation document with the SDK headers, following at most ten
 * HTTPS redirects, within 30 seconds, capped at 32 MiB while the body
 * streams. A bad host or nonce is a {@link ConfigurationError}; everything
 * else that fails is a {@link NetworkError}. `signal` ends the fetch early;
 * the timeout applies either way.
 */
export async function fetchDocument(host: string, relay: string | undefined, nonce: Uint8Array, fetchImpl: Fetch = fetch, signal?: AbortSignal): Promise<Uint8Array> {
  const target = attestationURL(host, relay, nonce);
  try {
    const response = await getFollowingRedirects(target, fetchImpl, signal);
    if (response.status > 299) {
      await response.body?.cancel();
      throw new Error(`HTTP GET ${target}: ${response.status} ${response.statusText}`);
    }
    return await readBounded(response, MAX_ATTESTATION_BYTES);
  } catch (err) {
    if (err instanceof TinfoilError) throw err;
    throw new NetworkError(messageOf(err), { cause: err });
  }
}

async function getFollowingRedirects(url: string, fetchImpl: Fetch, signal: AbortSignal | undefined): Promise<Response> {
  const timeout = AbortSignal.timeout(ATTESTATION_FETCH_TIMEOUT_MS);
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
async function readBounded(response: Response, limit: number): Promise<Uint8Array> {
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
      throw new Error(`attestation document exceeds ${limit} bytes`);
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
