/**
 * The gateway's catalog: which models it serves, from which repository, on
 * which replica hosts. It is untrusted; replicas are verified when used.
 * A client fetches it on first use and refreshes it on use every ten
 * seconds, which is how often the gateway reloads its own configuration.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import { parseReference } from "@tinfoilsh/verifier/v3";
import { messageOf, NetworkError, TinfoilError } from "../../errors.js";
import type { Catalog, CatalogEntry, Fetch } from "../../options.js";
import { getFollowingRedirects, readBounded } from "../fetch.js";

export const CATALOG_PATH = "/catalog";
export const CATALOG_FETCH_TIMEOUT_MS = 10_000;
export const CATALOG_REFRESH_INTERVAL_MS = 10_000;
export const MAX_CATALOG_BYTES = 2 << 20;
export const TRUSTED_REPO_OWNER = "tinfoilsh/";

/**
 * Reads the catalog of the gateway at `host` with `fetchImpl`, keeping only
 * models with replicas of a bare `tinfoilsh/` repository, without a tag or
 * digest. Anything but a 200 response, or a body over the size cap or not
 * a JSON object of entries, is a {@link NetworkError}.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export async function fetchCatalogWith(host: string, fetchImpl: Fetch, signal?: AbortSignal): Promise<Catalog> {
  const url = `https://${host}${CATALOG_PATH}`;
  let response: Response;
  try {
    response = await getFollowingRedirects(url, fetchImpl, signal, CATALOG_FETCH_TIMEOUT_MS);
  } catch (err) {
    if (err instanceof TinfoilError) throw err;
    throw new NetworkError(`fetching gateway catalog: ${messageOf(err)}`, { cause: err });
  }
  if (response.status !== 200) {
    await response.body?.cancel();
    throw new NetworkError(`fetching gateway catalog: ${response.status} ${response.statusText}`);
  }
  let body: Uint8Array;
  try {
    body = await readBounded(response, MAX_CATALOG_BYTES, "gateway catalog");
  } catch (err) {
    if (err instanceof TinfoilError) throw err;
    throw new NetworkError(`reading gateway catalog: ${messageOf(err)}`, { cause: err });
  }
  return parseCatalog(body);
}

/**
 * Decodes a catalog's JSON, keeping the trusted entries; a malformed document is a {@link NetworkError}.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function parseCatalog(body: Uint8Array): Catalog {
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch (err) {
    throw new NetworkError(`decoding gateway catalog: ${messageOf(err)}`, { cause: err });
  }
  const catalog = new Map<string, CatalogEntry>();
  if (decoded === null) return catalog;
  if (typeof decoded !== "object" || Array.isArray(decoded)) throw new NetworkError("decoding gateway catalog: not a JSON object");
  for (const [model, value] of Object.entries(decoded as Record<string, unknown>)) {
    const entry = catalogEntry(value);
    if (entry === undefined) throw new NetworkError(`decoding gateway catalog: model ${JSON.stringify(model)} has a malformed entry`);
    if (trusted(entry)) catalog.set(model, entry);
  }
  return catalog;
}

/** The entry `value` describes, with absent fields empty; undefined when a present field has the wrong type. */
function catalogEntry(value: unknown): CatalogEntry | undefined {
  if (value === null) return { repo: "", hosts: [] };
  if (typeof value !== "object" || Array.isArray(value)) return undefined;
  const { repo, hosts } = value as { repo?: unknown; hosts?: unknown };
  if (repo !== undefined && repo !== null && typeof repo !== "string") return undefined;
  if (hosts !== undefined && hosts !== null && !(Array.isArray(hosts) && hosts.every((h) => typeof h === "string"))) return undefined;
  return { repo: (repo as string | undefined) ?? "", hosts: Object.freeze([...((hosts as string[] | undefined) ?? [])]) };
}

/**
 * Whether an entry names a bare repository of the trusted owner and at least one replica.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function trusted(entry: CatalogEntry | undefined): entry is CatalogEntry {
  if (entry === undefined) return false;
  try {
    const ref = parseReference(entry.repo);
    return ref.repo === entry.repo && entry.repo.startsWith(TRUSTED_REPO_OWNER) && entry.hosts.length > 0;
  } catch {
    return false;
  }
}

/**
 * A catalog fetched on first use and refreshed on use once the interval has
 * passed. Concurrent callers share one fetch. Until a fetch succeeds,
 * callers wait for it and a failure is retried on the next use. After that,
 * callers never wait: the stale catalog is returned while a refresh runs,
 * and a failed refresh keeps it for another interval.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export class CatalogCache {
  readonly #fetch: (signal?: AbortSignal) => Promise<Catalog>;
  readonly #clock: () => Date;
  #catalog: Catalog | undefined;
  #loading: Promise<Catalog> | undefined;
  /** When the next refresh may start. */
  #refreshAt = 0;

  constructor(fetchCatalog: (signal?: AbortSignal) => Promise<Catalog>, clock: () => Date = () => new Date()) {
    this.#fetch = fetchCatalog;
    this.#clock = clock;
  }

  get(signal?: AbortSignal): Promise<Catalog> {
    if (this.#catalog !== undefined) {
      if (this.#clock().getTime() >= this.#refreshAt) {
        // Moving the next refresh ahead now, not when the fetch finishes,
        // keeps later callers from starting another while this one runs.
        this.#refreshAt = this.#clock().getTime() + CATALOG_REFRESH_INTERVAL_MS;
        this.#load().catch(() => {});
      }
      return Promise.resolve(this.#catalog);
    }
    return raceWithSignal(this.#load(), signal);
  }

  #load(): Promise<Catalog> {
    if (this.#loading === undefined) {
      // One fetch serves every waiter, so no single caller's signal applies;
      // the fetch has its own timeout.
      this.#loading = this.#fetch()
        .then((catalog) => {
          this.#catalog = catalog;
          return catalog;
        })
        .finally(() => {
          this.#loading = undefined;
          if (this.#catalog !== undefined) this.#refreshAt = this.#clock().getTime() + CATALOG_REFRESH_INTERVAL_MS;
        });
    }
    return this.#loading;
  }
}

/** `promise`, or `signal`'s reason as soon as it aborts, leaving the shared work running. */
function raceWithSignal<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) return Promise.reject(signal.reason as Error);
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(signal.reason as Error);
    signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
