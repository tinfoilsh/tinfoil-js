/**
 * Discovers Tinfoil's router: the first router from Tinfoil's router list
 * that verifies under the policy and passes the caller's check, and
 * otherwise inference.tinfoil.sh, left to be verified on first use. The list
 * fetch and every probe share one 30-second budget, so a long list of
 * unreachable routers can't hold up a client before it falls back.
 */
import type { Pin, Verifier } from "@tinfoilsh/verifier";
import { wrapNetwork } from "../errors.js";
import type { AttestationFetcher, Fetch, OnVerificationAttempt, RouterListFetcher, VerificationCheck } from "../options.js";
import { Enclave, type EnclaveConfig } from "./enclave.js";
import { getFollowingRedirects, isAuthority, readBounded, untilAborted } from "./fetch.js";
import { KeyedTransport, type Mode } from "./transport/transport.js";

// Tinfoil owns the router's name in both namespaces.
export const DEFAULT_ROUTER_NAME = "tinfoilsh/confidential-model-router";
export const DEFAULT_ROUTER_PIN: Pin = Object.freeze({ repo: DEFAULT_ROUTER_NAME, project: DEFAULT_ROUTER_NAME });
export const DEFAULT_ROUTER_URL = "https://atc.tinfoil.sh/routers";
/** The path of the router list, under Tinfoil's origin or a relay's URL. */
export const ROUTER_LIST_PATH = "/routers";
export const FALLBACK_ROUTER_HOST = "inference.tinfoil.sh";
export const ROUTER_FETCH_TIMEOUT_MS = 30_000;
export const DISCOVERY_TIMEOUT_MS = 30_000;
export const MAX_ROUTER_BYTES = 32 << 20;

export interface DiscoveryConfig {
  readonly verifier?: Verifier;
  readonly verificationCheck?: VerificationCheck;
  /** Called with the outcome of each attempt to verify a router: each candidate, and the fallback once it is verified. */
  readonly onVerificationAttempt?: OnVerificationAttempt;
  readonly mode: Mode;
  readonly signal?: AbortSignal;
  /** How each router's attestation document is obtained; undefined fetches it directly. */
  readonly fetchAttestation?: AttestationFetcher;
  /** How the router list is obtained; undefined fetches Tinfoil's list. */
  readonly fetchRouterList?: RouterListFetcher;
  /** Seams for tests: the fetch for Tinfoil's router list, the shuffle, and the enclave's seams. */
  readonly routersFetch?: Fetch;
  readonly shuffle?: <T>(items: readonly T[]) => T[];
  readonly documentFetch?: Fetch;
  readonly clock?: () => Date;
  readonly nonce?: () => Uint8Array;
  readonly sleep?: EnclaveConfig["sleep"];
}

/**
 * The transport for the first router that verifies, or for the fallback,
 * unverified. A candidate's failed verification moves discovery on, and so
 * does a list entry that isn't a host, since the list is untrusted input;
 * only a policy that can't be used stops discovery. Ends early when `signal`
 * aborts.
 */
export async function discoverRouter(config: DiscoveryConfig): Promise<KeyedTransport> {
  const clock = config.clock ?? (() => new Date());
  const enclaveFor = (host: string): Promise<Enclave> =>
    Enclave.create({
      host,
      pin: DEFAULT_ROUTER_PIN,
      verifier: config.verifier,
      verificationCheck: config.verificationCheck,
      onVerificationAttempt: config.onVerificationAttempt,
      fetchAttestation: config.fetchAttestation,
      fetch: config.documentFetch,
      clock: config.clock,
      nonce: config.nonce,
      sleep: config.sleep,
    });
  const fallback = await enclaveFor(FALLBACK_ROUTER_HOST);
  const deadline = clock().getTime() + DISCOVERY_TIMEOUT_MS;
  const budget = AbortSignal.timeout(DISCOVERY_TIMEOUT_MS);
  const probing = config.signal === undefined ? budget : AbortSignal.any([config.signal, budget]);

  let listed: readonly unknown[] = [];
  try {
    listed = config.fetchRouterList === undefined ? await fetchRouters(config.routersFetch ?? ((input, init) => fetch(input, init)), probing) : await listFrom(config.fetchRouterList, probing);
  } catch {
    // An unreachable or malformed list, or a fetcher's error, leaves the fallback.
  }
  // A copy, so that a caller's array is never reordered.
  const routers = (config.shuffle ?? shuffled)(listed);
  for (const router of routers) {
    // The deadline can pass before the budget's timer fires.
    if (probing.aborted || clock().getTime() >= deadline) break;
    if (typeof router !== "string" || !isAuthority(router)) continue;
    let candidate: KeyedTransport | undefined;
    try {
      candidate = new KeyedTransport(await enclaveFor(router), config.mode, config.clock);
      // The candidate keeps its verification, so the client doesn't repeat
      // it, and a router whose keys the mode can't use is skipped. When the
      // budget ends, discovery stops waiting; the fetch runs out on its own
      // timeout.
      await candidate.verifyOnce(probing);
      return candidate;
    } catch {
      // A probe that the budget or the caller's signal cut short goes on
      // inside the candidate. Closing the candidate releases what that
      // verification binds once it finishes, instead of leaving it to a
      // transport that nobody holds.
      candidate?.close();
      continue;
    }
  }
  config.signal?.throwIfAborted();
  return new KeyedTransport(fallback, config.mode, config.clock);
}

/**
 * The list that a caller's fetcher returns, within the discovery budget: a
 * result that isn't an array of strings, like an error, counts as an empty
 * list, so discovery falls back.
 */
async function listFrom(fetcher: RouterListFetcher, signal: AbortSignal): Promise<readonly unknown[]> {
  const listed: unknown = await untilAborted(Promise.resolve().then(() => fetcher({ signal })), signal);
  if (!Array.isArray(listed) || !listed.every((r) => typeof r === "string")) return [];
  return listed;
}

/** Tinfoil's router list: a JSON array of hosts, fetched within its own timeout and size cap over HTTPS only. */
export function fetchRouters(fetchImpl: Fetch, signal?: AbortSignal): Promise<string[]> {
  return fetchRouterListFrom(DEFAULT_ROUTER_URL, fetchImpl, signal);
}

/**
 * The router list at `url`, Tinfoil's or a relay's: a JSON array of hosts,
 * fetched within its own timeout and size cap with no redirect to a URL that
 * isn't HTTPS. Any failure is a {@link NetworkError}, which discovery takes
 * as an empty list.
 */
export async function fetchRouterListFrom(url: string, fetchImpl: Fetch, signal?: AbortSignal): Promise<string[]> {
  try {
    const response = await getFollowingRedirects(url, fetchImpl, signal, ROUTER_FETCH_TIMEOUT_MS);
    if (response.status > 299) {
      await response.body?.cancel();
      throw new Error(`fetching routers from ${url}: ${response.status} ${response.statusText}`);
    }
    const body = await readBounded(response, MAX_ROUTER_BYTES, `router list from ${url}`);
    const routers: unknown = JSON.parse(new TextDecoder().decode(body));
    if (!Array.isArray(routers) || !routers.every((r) => typeof r === "string")) {
      throw new Error(`router list from ${url} is not an array of hosts`);
    }
    return routers;
  } catch (err) {
    throw wrapNetwork(err);
  }
}

/** A uniformly shuffled copy of `items`, so that clients spread across routers. */
export function shuffled<T>(items: readonly T[]): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}
