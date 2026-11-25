/**
 * An HTTP client for Tinfoil inference through the gateway. Each request is
 * sealed to a verified replica of the model it names, as with the `"ehbp"`
 * transport: the gateway sees the method, URL and headers, and protocol
 * upgrades are refused.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import type { VerificationReport } from "@tinfoilsh/verifier";
import { ehbpOptionsFor, type EnclaveClientSeams } from "./enclave-client.js";
import { ConfigurationError } from "./errors.js";
import { resolveUserCacheSecret } from "./internal/cachesecret.js";
import { registerRoute } from "./internal/api-path.js";
import { asyncDispose } from "./internal/dispose.js";
import { isAuthority } from "./internal/fetch.js";
import { fetchCatalogWith } from "./internal/gateway/catalog.js";
import { GatewayPolicy } from "./internal/gateway/policy.js";
import { GatewayTransport } from "./internal/gateway/transport.js";
import { normalizeBaseURL, validateBaseURL } from "./internal/transport/base-url.js";
import { withOriginRestriction } from "./internal/transport/origin.js";
import type { CallOptions, Catalog, Fetch, GatewayOptions, ReplicaVerification } from "./options.js";

/**
 * Tinfoil's gateway, used when no `url` option is given: its origin, under
 * which an `OpenAIClient` joins its API path.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export const DEFAULT_GATEWAY_URL = "https://inference-gateway.tinfoil.sh/";

/** @internal Seams for tests: the enclave client's, the catalog fetch, and the secret resolution. */
export interface GatewayClientSeams extends Omit<EnclaveClientSeams, "tls"> {
  readonly catalogFetch?: Fetch;
  readonly resolveSecret?: (explicit: string | undefined) => string;
}

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const TOKEN: unique symbol = Symbol("GatewayHTTPClient");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (transport: GatewayTransport, baseURL: string, fetchImpl: Fetch) => GatewayHTTPClient;

/** @internal The factory with its test seams; {@link GatewayHTTPClient.create} is this without them. */
export async function createGatewayHTTPClient(options: GatewayOptions, seams: GatewayClientSeams): Promise<GatewayHTTPClient> {
  const given = options.url === undefined || options.url === "" ? DEFAULT_GATEWAY_URL : options.url;
  let base: URL;
  try {
    base = new URL(given);
  } catch {
    throw new ConfigurationError(`gateway base URL must be an absolute HTTPS URL: ${JSON.stringify(given)}`);
  }
  if (base.protocol !== "https:" || base.host === "") throw new ConfigurationError(`gateway base URL must be an absolute HTTPS URL: ${JSON.stringify(given)}`);
  // Credentials in the URL would go out in plaintext to the gateway with every request.
  if (base.username !== "" || base.password !== "") throw new ConfigurationError("gateway base URL must not carry a username or password");
  // The rules every base URL follows, such as no query string or fragment; HTTPS is already required above.
  validateBaseURL(given, "gateway URL");
  const baseURL = normalizeBaseURL(given);
  const policy = await GatewayPolicy.create(
    options.modelPins,
    options.policy,
    seams.verifier === undefined ? undefined : () => Promise.resolve(seams.verifier!),
  );
  const secret = (seams.resolveSecret ?? resolveUserCacheSecret)(options.userCacheSecret);
  const transport = new GatewayTransport({
    baseURL,
    catalog: options.catalog,
    policy,
    verificationCheck: options.verificationCheck,
    onVerificationAttempt: options.onVerificationAttempt,
    secret,
    catalogFetch: seams.catalogFetch,
    documentFetch: seams.documentFetch,
    clock: seams.clock,
    nonce: seams.nonce,
    sleep: seams.sleep,
    ehbp: ehbpOptionsFor(options.fetch, seams),
  });
  const client = construct(transport, baseURL, withOriginRestriction(transport.fetch, "", baseURL));
  // An unreachable gateway fails here rather than on the first request.
  await client.models({ signal: options.signal });
  return client;
}

/**
 * The HTTP client for Tinfoil inference through the gateway; see the module
 * header for what it protects. The constructor is private: type-checked
 * code cannot call it, and a call from untyped code is refused at runtime.
 * Clients come from {@link GatewayHTTPClient.create}. An `OpenAIClient`
 * from `tinfoil/openai` can be built over one.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export class GatewayHTTPClient {
  /** As {@link EnclaveHTTPClient.fetch}. */
  readonly fetch: Fetch;
  /**
   * The gateway's URL, the `url` option or Tinfoil's gateway by default:
   * its origin, or the URL that it is mounted under, never the API path.
   * Requests are sent under it, and an `OpenAIClient` joins its API path
   * under it, as under an enclave client's EHBP proxy. Always ends with `/`,
   * so a relative path resolves against it with
   * `new URL(path, client.baseURL)`.
   */
  readonly baseURL: string;
  readonly #transport: GatewayTransport;

  private constructor(token: typeof TOKEN, transport: GatewayTransport, baseURL: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("GatewayHTTPClient is created with GatewayHTTPClient.create");
    this.#transport = transport;
    this.fetch = fetchImpl;
    this.baseURL = baseURL;
    registerRoute(this, "gateway");
    // The client's state lives in the transport; the client itself never changes once created.
    Object.freeze(this);
  }

  static {
    construct = (...parts) => new GatewayHTTPClient(TOKEN, ...parts);
  }

  /**
   * Checks the options before any network I/O, then fetches the catalog
   * before returning. The client serves only the models that `modelPins`
   * names, so options without a pin are a {@link ConfigurationError}. A
   * model's replicas are verified on its first request, so `modelPins` may
   * name models that the catalog doesn't list. Without a
   * non-empty `userCacheSecret`, the client uses the secret that is generated
   * once for the current runtime; when it can't be generated, because
   * `crypto.getRandomValues` throws, the promise rejects with that error
   * unchanged, before any network I/O.
   */
  static create(options: GatewayOptions): Promise<GatewayHTTPClient> {
    // Untyped code may still pass nothing, which is refused as having no pins.
    return createGatewayHTTPClient(options ?? ({} as GatewayOptions), {});
  }

  /**
   * The catalog's models that the client's policy serves, sorted, without
   * verifying replicas. A failed catalog refresh doesn't fail it; only the
   * first fetch can.
   */
  models(options?: CallOptions): Promise<string[]> {
    return this.#transport.models(options?.signal);
  }

  /** The report of a verification valid now of a replica serving `model`, verifying replicas only if needed. */
  ensureVerified(model: string, options?: CallOptions): Promise<VerificationReport> {
    return this.#transport.ensureVerified(model, options?.signal);
  }

  /**
   * Verifies again the replica that {@link ensureVerified} would return for
   * `model`, even if its cached verification is still valid, and returns the
   * new report. It tries the model's replicas in the order that
   * `ensureVerified` tries them, verifying each again, and stops at the first
   * that passes, or that fails but keeps a valid verification, which requests
   * for `model` still use; it then rejects with that failure. Each failure
   * follows the rule that {@link EnclaveHTTPClient.reverify} describes, for
   * its replica: an {@link AttestationError} discards the replica's cached
   * verification, so that `reverify` moves on to the next replica, as
   * `ensureVerified` then does, and a failure of any other category keeps it
   * while it is still valid. When no replica passes or keeps a valid
   * verification, it rejects with the last failure. A model without a pin is
   * a {@link ConfigurationError}, and nothing is verified.
   */
  reverify(model: string, options?: CallOptions): Promise<VerificationReport> {
    return this.#transport.reverify(model, options?.signal);
  }

  /**
   * One entry for each replica that the client has tried to verify, failed
   * replicas included, without network I/O, sorted by host. An entry's
   * `current` follows the rule of {@link EnclaveHTTPClient.currentVerification}
   * for its replica: the report of the replica's verification while it is
   * fresh and has not been discarded, and undefined otherwise. Its
   * `lastAttempt` holds the replica's most recent attempt, as
   * {@link EnclaveHTTPClient.lastVerificationAttempt} describes: a failed
   * attempt replaces an earlier success there, though `current` keeps that
   * success while the failure leaves it valid. A new array of copies on each
   * call.
   */
  replicas(): ReplicaVerification[] {
    return this.#transport.replicas();
  }

  /**
   * Refuses further use: `fetch`, `models`, `ensureVerified` and `reverify`
   * reject with a {@link ConfigurationError} afterwards, and no replica is
   * verified again; `replicas` still reports the replicas' last attempts,
   * with no current verification.
   * Requests are sealed and sent through the runtime's fetch, or the `fetch`
   * option, so the client holds no connections of its own to release; a sealed exchange already
   * under way completes, while a request still preparing, verifying or
   * rerouting rejects as closed. Closing again does nothing.
   */
  async close(): Promise<void> {
    this.#transport.close();
  }

  /** Closes the client at the end of an `await using` block; see {@link close}. */
  [asyncDispose](): Promise<void> {
    return this.close();
  }
}

/**
 * Reads the catalog of the gateway at the root of `host`, a host with an
 * optional port, from `https://{host}/catalog`, keeping only models with
 * replicas of a bare `tinfoilsh/` repository, without a tag or digest. The
 * catalog is untrusted: replicas are verified when they are used.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export async function fetchCatalog(host: string, options?: CallOptions): Promise<Catalog> {
  if (!isAuthority(host)) throw new ConfigurationError(`invalid gateway host ${JSON.stringify(host)}: want a host with an optional port`);
  return fetchCatalogWith(`https://${host}/`, (input, init) => fetch(input, init), options?.signal);
}
