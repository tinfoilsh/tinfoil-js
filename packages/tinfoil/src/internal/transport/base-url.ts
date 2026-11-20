/**
 * The rules for a client's route URL: an EHBP proxy that requests go to
 * instead of the enclave's own origin, or the gateway's URL.
 */
import { ConfigurationError } from "../../errors.js";
import { originOf } from "./origin.js";

/**
 * Requires an absolute URL that keeps request headers private on the way to
 * the enclave or proxy: HTTPS, or HTTP to a loopback host, whose traffic
 * never leaves the machine. A query string or fragment is refused, since a
 * path resolved against the base would drop it; so are credentials, which
 * a request can't be built from, and which no error repeats: they are
 * refused before any error that names the URL.
 */
export function validateBaseURL(baseURL: string, name = "base URL"): void {
  let origin: string;
  try {
    origin = originOf(baseURL);
  } catch (err) {
    throw new ConfigurationError(`invalid ${name}: ${(err as Error).message}`, { cause: err });
  }
  const url = new URL(baseURL);
  if (url.username !== "" || url.password !== "") {
    throw new ConfigurationError(`invalid ${name}: a username or password can't be part of a ${name}`);
  }
  if (baseURL.includes("?") || baseURL.includes("#")) {
    throw new ConfigurationError(`invalid ${name}: a query string or fragment can't be part of a ${name}: ${JSON.stringify(baseURL)}`);
  }
  if (origin.startsWith("https://")) return;
  if (!isLoopback(url.hostname)) {
    throw new ConfigurationError(`invalid ${name}: HTTP is allowed only for localhost or a loopback IP address; use HTTPS to protect request headers`);
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

/**
 * Refuses a proxy URL on the enclave's own origin, which would send
 * requests directly to the enclave under the name of a proxy.
 */
export function refuseEnclaveOriginProxy(proxyURL: string, enclave: string): void {
  if (proxyURL === "") return;
  let proxyOrigin: string;
  let enclaveOrigin: string;
  try {
    proxyOrigin = originOf(proxyURL);
    enclaveOrigin = originOf(`https://${enclave}`);
  } catch (err) {
    throw new ConfigurationError(`invalid proxy URL: ${(err as Error).message}`, { cause: err });
  }
  if (proxyOrigin === enclaveOrigin) {
    throw new ConfigurationError(`invalid proxy URL: ${JSON.stringify(enclaveOrigin)} is the enclave's own origin; leave proxyURL unset to connect directly`);
  }
}
