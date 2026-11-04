/**
 * Routes requests through Tinfoil's inference gateway, sealing each to a
 * verified replica of the model it names. The gateway sees the method, URL
 * and headers and forwards the sealed body to the replica named in the
 * enclave header; a replica is verified, through the gateway, before
 * anything is sealed to it. Cache prefixes keep a conversation on the same
 * replica across requests, and a gateway that routes a request elsewhere
 * answers 412 naming the replica it chose, which the request follows after
 * verifying it.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { AttestationError, ConfigurationError, messageOf, NetworkError, type TinfoilError } from "../../errors.js";
import type { Catalog, Fetch, ReplicaVerification, VerificationCheck } from "../../options.js";
import { Enclave, type EnclaveConfig } from "../enclave.js";
import { checkEHBP, ehbpMode, type EHBPOptions } from "../transport/ehbp.js";
import { withEnclaveURL } from "../transport/header.js";
import { withReplay } from "../transport/replay.js";
import { isKeyRejection, KeyedTransport, optionsOf, shapeOf } from "../transport/transport.js";
import { CatalogCache, fetchCatalogWith } from "./catalog.js";
import { GatewayPolicy, replicaKey, type Replica } from "./policy.js";
import { CACHE_PREFIX_HEADER, MODEL_HEADER, prepare } from "./prepare.js";

export const SEAL_HEADER = "X-Tinfoil-Seal";
export const MAX_SEAL_REDIRECTS = 3;
export const MAX_REROUTED = 1024;

/** @experimental The gateway route is new; this API may change without a major version. */
export interface GatewayTransportConfig {
  /** Where requests are sent, and the gateway host that attestation is fetched through. */
  readonly baseURL: string;
  readonly relay: string;
  /** Read on every request; undefined fetches it from the relay on first use and refreshes it. */
  readonly catalog?: () => Catalog;
  readonly policy: GatewayPolicy;
  readonly verificationCheck?: VerificationCheck;
  /** The resolved client-level cache secret; "" scopes nothing. */
  readonly secret: string;
  /** Seams for tests. */
  readonly catalogFetch?: Fetch;
  readonly documentFetch?: Fetch;
  readonly clock?: () => Date;
  readonly nonce?: () => Uint8Array;
  readonly sleep?: EnclaveConfig["sleep"];
  readonly ehbp?: EHBPOptions;
}

/** One replica's verified transport, and the models requests to it named. */
interface ReplicaTransport {
  readonly keyed: KeyedTransport;
  readonly fetch: Fetch;
  readonly models: Set<string>;
}

/** @experimental The gateway route is new; this API may change without a major version. */
export class GatewayTransport {
  readonly #config: GatewayTransportConfig;
  readonly #catalog: (signal?: AbortSignal) => Promise<Catalog>;
  /** Each replica's transport while it is being built, then once built. */
  readonly #pending = new Map<string, Promise<ReplicaTransport>>();
  readonly #replicas = new Map<string, ReplicaTransport>();
  /** Cache prefix to the host the gateway last routed it to. */
  #rerouted = new Map<string, string>();
  /** Sends a request to a verified replica of the model it names. */
  readonly fetch: Fetch;

  constructor(config: GatewayTransportConfig) {
    this.#config = config;
    if (config.catalog !== undefined) {
      const read = config.catalog;
      this.#catalog = () => Promise.resolve(read());
    } else {
      const cache = new CatalogCache((signal) => fetchCatalogWith(config.relay, config.catalogFetch ?? ((input, init) => fetch(input, init)), signal), config.clock);
      this.#catalog = (signal) => cache.get(signal);
    }
    this.fetch = (input, init) => this.#send(input, init);
  }

  /** The catalog's models that the policy serves, sorted, without verifying replicas. */
  async models(signal?: AbortSignal): Promise<string[]> {
    signal?.throwIfAborted();
    const catalog = await this.#catalog(signal);
    return [...catalog.keys()].filter((model) => this.#config.policy.serves(model, catalog)).sort();
  }

  /**
   * A valid verification of a replica serving `model`, trying replicas in a
   * fixed order for the model so repeated calls verify the same replica
   * while it stays valid. Stops once `signal` aborts.
   */
  async ensureVerified(model: string, signal?: AbortSignal): Promise<Verification> {
    const catalog = await this.#catalog(signal);
    const { hosts, replica } = this.#config.policy.resolve(model, catalog);
    let failure: unknown;
    for (const host of await rank(hosts, model, undefined)) {
      signal?.throwIfAborted();
      try {
        return (await this.#verified({ ...replica, host }, signal)).keyed.current()!;
      } catch (err) {
        failure = err;
      }
    }
    throw failure;
  }

  /** The last successful verification of each replica used so far, unchecked, in host order. */
  verifications(): ReplicaVerification[] {
    const results: ReplicaVerification[] = [];
    for (const [key, rt] of this.#replicas) {
      const verification = rt.keyed.current();
      if (verification === undefined) continue;
      const [host, reference, pinnedModel] = key.split("\0") as [string, string, string];
      results.push({ host, models: [...rt.models].sort(), reference, pinnedModel, verification });
    }
    return results.sort((a, b) => compare(a.host, b.host) || compare(a.reference, b.reference) || compare(a.pinnedModel, b.pinnedModel));
  }

  async #send(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const shape = shapeOf(input, init);
    // Each replica's EHBP transport makes the same check; making it here
    // refuses a request before the catalog is read or a replica verified.
    checkEHBP(shape);
    const request = input instanceof Request ? input : undefined;
    // A Request carries a signal of its own; the init's takes precedence, as fetch has it.
    const signal = init?.signal ?? request?.signal;
    const original = init?.body !== undefined ? init.body : request?.body;
    const prepared = await prepare(shape, shape.headers, original, this.#config.secret, undefined, signal);
    const model = prepared.headers.get(MODEL_HEADER) ?? "";
    const catalog = await this.#catalog(signal);
    const { hosts, replica } = this.#config.policy.resolve(model, catalog);
    const prefix = prepared.headers.get(CACHE_PREFIX_HEADER) ?? "";
    let host = "";
    let rt: ReplicaTransport | undefined;
    let failure: unknown;
    for (host of await rank(hosts, prefix, this.#rerouted.get(prefix))) {
      try {
        rt = await this.#verified({ ...replica, host }, signal);
        break;
      } catch (err) {
        failure = err;
      }
    }
    if (rt === undefined) throw failure;
    const url = shape.url.toString();
    for (let redirects = 0; ; redirects++) {
      const headers = new Headers(prepared.headers);
      headers.set(SEAL_HEADER, host);
      rt.models.add(model);
      // A Request input's other options travel with the rebuilt request.
      const forwarded: RequestInit = { ...(request === undefined ? {} : optionsOf(request)), ...init, method: shape.method, headers, body: prepared.body, signal };
      const response = await rt.fetch(url, forwarded);
      const routed = response.headers.get(SEAL_HEADER) ?? "";
      if (response.status !== 412 || routed === "" || routed === host || !prepared.replayable) return response;
      await response.body?.cancel();
      if (redirects === MAX_SEAL_REDIRECTS) {
        throw new NetworkError(`gateway kept routing away from the enclave the request was sealed to (last: ${routed})`);
      }
      host = routed;
      try {
        rt = await this.#verified({ ...replica, host }, signal);
      } catch (err) {
        // A caller that gave up during the reroute gets its own reason back.
        if (signal?.aborted) throw err;
        throw rewrap(err, `following gateway route to enclave ${routed}: ${messageOf(err)}`);
      }
      this.#remember(prefix, routed);
    }
  }

  /** `r`'s transport once its replica verifies, so a caller can fall over to another replica before sealing anything to it. */
  async #verified(r: Replica, signal: AbortSignal | undefined): Promise<ReplicaTransport> {
    const rt = await this.#replica(r);
    await rt.keyed.ensureVerified(signal);
    return rt;
  }

  /** One transport per replica, shared by concurrent first uses; a replica that can't be built is retried on its next use. */
  #replica(r: Replica): Promise<ReplicaTransport> {
    const key = replicaKey(r);
    const built = this.#replicas.get(key);
    if (built !== undefined) return Promise.resolve(built);
    let pending = this.#pending.get(key);
    if (pending === undefined) {
      pending = this.#build(r);
      pending.then((rt) => this.#replicas.set(key, rt)).catch(() => {}).finally(() => this.#pending.delete(key));
      this.#pending.set(key, pending);
    }
    return pending;
  }

  async #build(r: Replica): Promise<ReplicaTransport> {
    const c = this.#config;
    const enclave = await Enclave.create({
      host: r.host,
      relay: c.relay,
      repo: r.ref,
      verifier: c.policy.verifierFor(r),
      verificationCheck: c.verificationCheck,
      fetch: c.documentFetch,
      clock: c.clock,
      nonce: c.nonce,
      sleep: c.sleep,
    });
    const keyed = new KeyedTransport(enclave, ehbpMode(c.ehbp), c.clock);
    return { keyed, fetch: replicaChain(keyed.fetch, r.host, c.baseURL), models: new Set() };
  }

  #remember(prefix: string, host: string): void {
    if (prefix === "") return;
    if (this.#rerouted.size >= MAX_REROUTED) this.#rerouted = new Map();
    this.#rerouted.set(prefix, host);
  }
}

/**
 * What a replica's requests go through around `keyed`, from the inside out: the proxy header, then one replay after a key rejection.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function replicaChain(keyed: Fetch, host: string, baseURL: string): Fetch {
  return withReplay(withEnclaveURL(keyed, host, baseURL), isKeyRejection);
}

/**
 * Orders hosts by rendezvous score for a cache prefix, with `first` moved to the front, or randomly without a prefix.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export async function rank(hosts: readonly string[], prefix: string, first: string | undefined): Promise<string[]> {
  const ranked = [...hosts];
  if (prefix === "") {
    for (let i = ranked.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [ranked[i], ranked[j]] = [ranked[j]!, ranked[i]!];
    }
    return ranked;
  }
  const scores = new Map<string, bigint>();
  for (const host of ranked) {
    const sum = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${prefix}\0${host}`)));
    scores.set(host, new DataView(sum.buffer).getBigUint64(0, false));
  }
  ranked.sort((a, b) => (scores.get(b)! < scores.get(a)! ? -1 : scores.get(b)! > scores.get(a)! ? 1 : 0));
  const index = first === undefined ? -1 : ranked.indexOf(first);
  if (index > 0) {
    ranked.splice(index, 1);
    ranked.unshift(first!);
  }
  return ranked;
}

/** `err` as a categorized error with `message`, in the category it already has, or configuration when it has none. */
function rewrap(err: unknown, message: string): TinfoilError {
  if (err instanceof NetworkError) return new NetworkError(message, { cause: err });
  if (err instanceof AttestationError) return new AttestationError(message, { cause: err });
  return new ConfigurationError(message, { cause: err });
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

