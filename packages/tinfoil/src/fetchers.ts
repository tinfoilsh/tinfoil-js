/**
 * Relay helpers for the `fetchAttestation` and `fetchRouterList` options:
 * fetchers that reach an enclave's attestation document and Tinfoil's router
 * list through a relay, such as an endpoint on the application's own origin
 * that forwards each request. With an EHBP `proxyURL` on the same origin, a
 * client in a browser then contacts nothing else, as a strict content
 * security policy requires.
 */
import { ConfigurationError } from "./errors.js";
import { fetchRelayedDocument } from "./internal/fetch.js";
import { fetchRouterListFrom, ROUTER_LIST_PATH } from "./internal/router.js";
import { normalizeBaseURL, validateBaseURL } from "./internal/transport/base-url.js";
import type { AttestationFetcher, Fetch, RouterListFetcher } from "./options.js";

/** Configures a relay helper. */
export interface RelayOptions {
  /**
   * The fetch that sends the relay's requests; undefined selects the
   * runtime's fetch, looked up when each request is sent.
   */
  readonly fetch?: Fetch;
}

/** `url` checked under the route URL rules and ending with `/`; a bad one is a {@link ConfigurationError}. */
function relayBase(url: string, name: string): string {
  if (typeof url !== "string" || url === "") throw new ConfigurationError(`invalid ${name}: it must be a non-empty string`);
  validateBaseURL(url, name);
  return normalizeBaseURL(url);
}

/** The fetch that `options` select. */
function fetchOf(options: RelayOptions | undefined): Fetch {
  const given = options?.fetch;
  if (given !== undefined && typeof given !== "function") throw new ConfigurationError("the relay's fetch must be a function");
  return given ?? ((input, init) => fetch(input, init));
}

/**
 * An {@link AttestationFetcher} that fetches documents through the relay at
 * `url`. For each document it sends
 * `GET {url}/.well-known/tinfoil-attestation?nonce={nonce}&enclave={host}`,
 * where `nonce` is the challenge in lowercase hex and `host` is the enclave's
 * host, with its port when it has one, encoded as a query value. The path
 * joins under the path of `url`, whether or not that path ends with `/`. The
 * request carries the SDK identity headers that a direct fetch carries, and
 * nothing that identifies the caller, such as the API key. A `2xx`
 * response's body is the document; the fetch has the bounds of a direct
 * fetch: 30 seconds, 32 MiB, and no redirect to a URL that isn't HTTPS. The
 * relay isn't trusted: the client verifies each document that it returns.
 *
 * `url` must use HTTPS, or HTTP to localhost or a loopback IP address, and
 * must carry no user information, query or fragment, even an empty one; a
 * bad one is a {@link ConfigurationError}, thrown here, before any network
 * I/O. The relay forwards each request to
 * `https://{enclave}/.well-known/tinfoil-attestation?nonce={nonce}`, and
 * should forward only to the enclave hosts that the application expects.
 */
export function attestationRelay(url: string, options?: RelayOptions): AttestationFetcher {
  const base = relayBase(url, "attestation relay URL");
  const fetchImpl = fetchOf(options);
  return (host, nonce, { signal }) => fetchRelayedDocument(base, host, nonce, fetchImpl, signal);
}

/**
 * A {@link RouterListFetcher} that fetches the router list through the relay
 * at `url`, which should forward the request to
 * `https://atc.tinfoil.sh/routers`. It sends `GET {url}/routers`, the path
 * joined under the path of `url` as {@link attestationRelay} joins its own,
 * and parses the response as a direct fetch's: a JSON array of host strings
 * of at most 32 MiB, fetched with no redirect to a URL that isn't HTTPS.
 * `url` follows the rules of {@link attestationRelay}, checked here.
 */
export function routerListRelay(url: string, options?: RelayOptions): RouterListFetcher {
  const base = relayBase(url, "router list relay URL");
  const fetchImpl = fetchOf(options);
  const target = `${base.replace(/\/$/, "")}${ROUTER_LIST_PATH}`;
  return ({ signal }) => fetchRouterListFrom(target, fetchImpl, signal);
}
