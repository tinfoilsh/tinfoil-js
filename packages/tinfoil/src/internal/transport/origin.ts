/**
 * Origin handling: the normalized origin of a URL, and the guard that keeps
 * a client's requests on the enclave it verified (or the proxy it was
 * configured with), so sensitive headers such as the API key never reach an
 * arbitrary host.
 */
import { ConfigurationError } from "../../errors.js";
import type { Fetch } from "../../options.js";

/** The URL a fetch call addresses, which must be absolute. */
export function requestURL(input: string | URL | Request): URL {
  try {
    if (input instanceof Request) return new URL(input.url);
    return input instanceof URL ? new URL(input.href) : new URL(input);
  } catch {
    throw new ConfigurationError(`request URL must be absolute: ${JSON.stringify(input instanceof Request ? input.url : String(input))}`);
  }
}

/** The normalized origin of an absolute http or https URL. */
export function originOf(rawURL: string): string {
  let u: URL;
  try {
    u = new URL(rawURL);
  } catch {
    throw new Error(`URL must be absolute: ${JSON.stringify(rawURL)}`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`URL must use http or https: ${JSON.stringify(rawURL)}`);
  if (u.host === "") throw new Error(`URL must be absolute: ${JSON.stringify(rawURL)}`);
  return normalizedOrigin(u);
}

/**
 * Lowercases the scheme and host and drops an explicit default port, so
 * origins compare equal however the URL spells them (https://host and
 * https://host:443).
 */
export function normalizedOrigin(u: URL): string {
  // URL already lowercases the scheme and host and drops the default port.
  return `${u.protocol}//${u.host}`;
}

/** The origins a client may send to: the enclave's and the base URL's; either may be empty. */
export function allowedOrigins(enclave: string, baseURL: string): Set<string> {
  const origins = new Set<string>();
  try {
    if (enclave !== "") origins.add(originOf(`https://${enclave}`));
    if (baseURL !== "") origins.add(originOf(baseURL));
  } catch (err) {
    throw new ConfigurationError(`failed to determine allowed request origins: ${(err as Error).message}`, { cause: err });
  }
  return origins;
}

/**
 * `next` behind a guard that refuses requests to any origin other than the
 * enclave and the base URL. Every API request that the client sends passes
 * through it, and the EHBP and TLS modes (`ehbp.ts`, `tls.ts`) hand a
 * redirect back rather than following it, so no API request goes out to an
 * origin the guard never saw. The client's own fetches of attestation
 * documents and catalogs take another path, not this one.
 */
export function withOriginRestriction(next: Fetch, enclave: string, baseURL: string): Fetch {
  const origins = allowedOrigins(enclave, baseURL);
  return (input, init) => {
    const origin = normalizedOrigin(requestURL(input));
    if (!origins.has(origin)) {
      return Promise.reject(new ConfigurationError(`refusing to send request to ${JSON.stringify(origin)}: client is bound to enclave ${JSON.stringify(enclave)}`));
    }
    return next(input, init);
  };
}
