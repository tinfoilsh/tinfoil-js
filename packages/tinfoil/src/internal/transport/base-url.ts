/**
 * The rules for a client's base URL: where requests go instead of the
 * enclave's own origin, which is a path on that origin or a proxy on
 * another.
 */
import { ConfigurationError } from "../../errors.js";
import { originOf } from "./origin.js";

/**
 * Requires an absolute URL that keeps request headers private on the way to
 * the enclave or proxy: HTTPS, or HTTP to a loopback host, whose traffic
 * never leaves the machine. A query string or fragment is refused, since a
 * path resolved against the base would drop it.
 */
export function validateBaseURL(baseURL: string): void {
  let origin: string;
  try {
    origin = originOf(baseURL);
  } catch (err) {
    throw new ConfigurationError(`invalid base URL: ${(err as Error).message}`, { cause: err });
  }
  if (baseURL.includes("?") || baseURL.includes("#")) {
    throw new ConfigurationError(`invalid base URL: a query string or fragment can't be part of a base URL: ${JSON.stringify(baseURL)}`);
  }
  if (origin.startsWith("https://")) return;
  if (!isLoopback(new URL(baseURL).hostname)) {
    throw new ConfigurationError("invalid base URL: HTTP is allowed only for localhost or a loopback IP address; use HTTPS to protect request headers");
  }
}

/**
 * `baseURL` as the URL parser reads it (surrounding whitespace dropped, the
 * host lowercased, a default port removed), with its path ending in `/` so
 * a relative path resolves under it rather than beside its last segment.
 * The caller has validated it, so it parses.
 */
export function normalizeBaseURL(baseURL: string): string {
  const url = new URL(baseURL);
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url.href;
}

/**
 * Whether `host`, as written, is localhost or a loopback IP address. Other
 * names are not resolved, so DNS can't make a remote host pass.
 */
export function isLoopback(host: string): boolean {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (bare.toLowerCase() === "localhost") return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare)) return true;
  return /^(0*:)+0*1$/.test(bare) || bare === "::1";
}

/** Requires a TLS-mode base URL to use the enclave's own origin, since a pinned connection can't pass through a proxy. */
export function validateTLSBaseURL(baseURL: string, enclave: string): void {
  if (baseURL === "") return;
  let baseOrigin: string;
  let enclaveOrigin: string;
  try {
    baseOrigin = originOf(baseURL);
    enclaveOrigin = originOf(`https://${enclave}`);
  } catch (err) {
    throw new ConfigurationError(`invalid base URL: ${(err as Error).message}`, { cause: err });
  }
  if (baseOrigin !== enclaveOrigin) {
    throw new ConfigurationError(`a base URL off the verified enclave origin ${JSON.stringify(enclaveOrigin)} is a proxy, which requires the EHBP transport mode`);
  }
}
