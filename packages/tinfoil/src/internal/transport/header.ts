/**
 * The header that tells a proxy which enclave to forward a request to, so a
 * proxied request reaches the enclave the client verified.
 */
import type { Fetch } from "../../options.js";
import { originOf } from "./origin.js";

export const ENCLAVE_URL_HEADER = "X-Tinfoil-Enclave-Url";

/** The header value when `baseURL` is a proxy on another origin than the enclave; undefined when requests go to the enclave itself. */
export function enclaveURLHeaderValue(enclave: string, baseURL: string): string | undefined {
  if (baseURL === "" || enclave === "") return undefined;
  const enclaveURL = `https://${enclave}`;
  let proxyOrigin: string;
  let enclaveOrigin: string;
  try {
    proxyOrigin = originOf(baseURL);
    enclaveOrigin = originOf(enclaveURL);
  } catch {
    return undefined;
  }
  return proxyOrigin === enclaveOrigin ? undefined : enclaveURL;
}

/**
 * Adds the enclave URL header to every request when `baseURL` is a proxy,
 * and otherwise returns `next`. The value is the verified enclave's host,
 * which never changes, so every request, including replays and requests
 * after re-verification, points at the enclave that was verified.
 */
export function withEnclaveURL(next: Fetch, enclave: string, baseURL: string): Fetch {
  const value = enclaveURLHeaderValue(enclave, baseURL);
  if (value === undefined) return next;
  return (input, init) => {
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.set(ENCLAVE_URL_HEADER, value);
    return next(input, { ...init, headers });
  };
}
