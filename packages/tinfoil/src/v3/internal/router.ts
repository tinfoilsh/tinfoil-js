/**
 * Discovers Tinfoil's router: the first router from Tinfoil's router list
 * that verifies under the policy and passes the caller's check, and
 * otherwise inference.tinfoil.sh, left to be verified on first use. The list
 * fetch and every probe share one 30-second budget, so a long list of
 * unreachable routers can't hold up a client before it falls back.
 */
import type { Verifier } from "@tinfoilsh/verifier";
import type { Fetch, VerificationCheck } from "../options.js";
import { Enclave, type EnclaveConfig } from "./enclave.js";
import { getFollowingRedirects, isAuthority, readBounded } from "./fetch.js";
import { KeyedTransport, type Mode } from "./transport/transport.js";

export const DEFAULT_ROUTER_REPO = "tinfoilsh/confidential-model-router";
export const DEFAULT_ROUTER_URL = "https://atc.tinfoil.sh/routers";
export const FALLBACK_ROUTER_HOST = "inference.tinfoil.sh";
export const ROUTER_FETCH_TIMEOUT_MS = 30_000;
export const DISCOVERY_TIMEOUT_MS = 30_000;
export const MAX_ROUTER_BYTES = 32 << 20;

export interface DiscoveryConfig {
  readonly verifier?: Verifier;
  readonly verificationCheck?: VerificationCheck;
  readonly mode: Mode;
  readonly signal?: AbortSignal;
  /** Seams for tests: the fetch for the router list, and the enclave's seams. */
  readonly routersFetch?: Fetch;
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
      repo: DEFAULT_ROUTER_REPO,
      verifier: config.verifier,
      verificationCheck: config.verificationCheck,
      fetch: config.documentFetch,
      clock: config.clock,
      nonce: config.nonce,
      sleep: config.sleep,
    });
  const fallback = await enclaveFor(FALLBACK_ROUTER_HOST);
  const deadline = clock().getTime() + DISCOVERY_TIMEOUT_MS;
  const budget = AbortSignal.timeout(DISCOVERY_TIMEOUT_MS);
  const probing = config.signal === undefined ? budget : AbortSignal.any([config.signal, budget]);

  let routers: string[] = [];
  try {
    routers = await fetchRouters(config.routersFetch ?? ((input, init) => fetch(input, init)), probing);
  } catch {
    // An unreachable or malformed list leaves the fallback.
  }
  for (const router of routers) {
    // The deadline can pass before the budget's timer fires.
    if (probing.aborted || clock().getTime() >= deadline) break;
    if (!isAuthority(router)) continue;
    try {
      const candidate = new KeyedTransport(await enclaveFor(router), config.mode, config.clock);
      // The candidate keeps its verification, so the client doesn't repeat
      // it, and a router whose keys the mode can't use is skipped. When the
      // budget ends, discovery stops waiting; the fetch runs out on its own
      // timeout.
      await candidate.verifyOnce(probing);
      return candidate;
    } catch {
      continue;
    }
  }
  config.signal?.throwIfAborted();
  return new KeyedTransport(fallback, config.mode, config.clock);
}

/** The router list: a JSON array of hosts, fetched within its own timeout and size cap over HTTPS only. */
export async function fetchRouters(fetchImpl: Fetch, signal?: AbortSignal): Promise<string[]> {
  const response = await getFollowingRedirects(DEFAULT_ROUTER_URL, fetchImpl, signal, ROUTER_FETCH_TIMEOUT_MS);
  if (response.status > 299) {
    await response.body?.cancel();
    throw new Error(`fetching routers from ${DEFAULT_ROUTER_URL}: ${response.status} ${response.statusText}`);
  }
  const body = await readBounded(response, MAX_ROUTER_BYTES, `router list from ${DEFAULT_ROUTER_URL}`);
  const routers: unknown = JSON.parse(new TextDecoder().decode(body));
  if (!Array.isArray(routers) || !routers.every((r) => typeof r === "string")) {
    throw new Error(`router list from ${DEFAULT_ROUTER_URL} is not an array of hosts`);
  }
  return routers;
}
