/**
 * The options the clients take, and the types their facts are reported in.
 * Every client checks its options before any network I/O, so a misconfigured
 * client fails at creation rather than on its first request.
 */
import type { Verification, Verifier } from "@tinfoilsh/verifier/v3";

/**
 * A client's `fetch`: the standard signature, bound to the client's attested
 * transport, so it can be handed to any library that takes a `fetch`.
 */
export type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/**
 * How a client protects its traffic to an enclave.
 *
 * - `"tls"` pins each connection to the attested TLS key. It protects the
 *   whole request and response and needs a direct connection, so it is the
 *   default where the runtime can inspect the connection (Node and Bun).
 * - `"ehbp"` seals request and response bodies to the attested HPKE key, so
 *   they stay private through a proxy. The method, URL and headers aren't
 *   sealed, and neither is a request without a body or its response. It
 *   refuses protocol upgrades and CONNECT tunnels. It is the only mode in
 *   browsers, and the default there.
 */
export type TransportMode = "tls" | "ehbp";

/**
 * Called with each verification that passes the verifier, before the client
 * uses the enclave's keys: when the client is created and whenever it
 * verifies again. Throw to reject the enclave; verification then fails with
 * an {@link AttestationError} wrapping the thrown value and isn't retried.
 * Requests wait while it runs, so keep it fast; it may run concurrently.
 */
export type VerificationCheck = (verification: Verification) => void | Promise<void>;

/** Configures an {@link EnclaveHTTPClient}. */
export interface EnclaveOptions {
  /** Defaults to `"tls"` on Node and Bun, `"ehbp"` in browsers. */
  readonly transportMode?: TransportMode;
  /**
   * A path on the enclave's own HTTPS origin, or a proxy on another origin,
   * which requires `"ehbp"`. Requests to a proxy carry `X-Tinfoil-Enclave-Url`
   * so it can forward them. A proxy must use HTTPS, since EHBP doesn't seal
   * headers such as the API key; `http://` is accepted only for localhost or
   * a loopback IP address.
   */
  readonly baseURL?: string;
  /** The verification policy; undefined selects the defaults. */
  readonly verifier?: Verifier;
  readonly verificationCheck?: VerificationCheck;
  /**
   * The default prompt-cache scope for the client's requests. Only Tinfoil's
   * router reads it, so set it when the enclave is a router. A non-empty
   * `user_cache_secret` string in a request's JSON body overrides it. Use an
   * opaque random value, not a raw user ID or API key.
   */
  readonly userCacheSecret?: string;
  /** Aborts the verification the factory performs before it returns. */
  readonly signal?: AbortSignal;
}

/** Configures a {@link RouterHTTPClient}. */
export interface RouterOptions {
  /** Defaults to `"tls"` on Node and Bun, `"ehbp"` in browsers. */
  readonly transportMode?: TransportMode;
  /**
   * A proxy that forwards requests to the router discovery chooses, which
   * requires `"ehbp"`: the router isn't known before discovery, so a base URL
   * can't name its origin. Requests carry `X-Tinfoil-Enclave-Url`. The proxy
   * must use HTTPS; `http://` is accepted only for localhost or a loopback IP
   * address.
   */
  readonly baseURL?: string;
  /**
   * The verification policy; undefined selects the defaults. A verifier that
   * authorizes the config itself is a {@link ConfigurationError}, since it
   * needs an explicit enclave.
   */
  readonly verifier?: Verifier;
  /**
   * Called for each router tried during discovery and whenever the client
   * verifies again. A rejection during discovery moves on to the next router;
   * otherwise it fails verification as for an enclave client.
   */
  readonly verificationCheck?: VerificationCheck;
  /**
   * The default prompt-cache scope; empty resolves it from the
   * `TINFOIL_USER_CACHE_SECRET` environment variable, then the secret
   * persisted at `~/.tinfoil/user_cache_secret`. A non-empty
   * `user_cache_secret` string in a request's JSON body overrides it.
   */
  readonly userCacheSecret?: string;
  /** Aborts discovery and the verification the factory performs before it returns. */
  readonly signal?: AbortSignal;
}

/**
 * Pins a model to `tinfoilsh/name[@tag][@sha256:digest]`.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export interface ModelPin {
  readonly repo: string;
  /** The pin's policy: undefined inherits {@link GatewayOptions.verifier}. */
  readonly verifier?: Verifier;
}

/**
 * One model's untrusted repository and replica hosts from a gateway catalog.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export interface CatalogEntry {
  readonly repo: string;
  readonly hosts: readonly string[];
}

/**
 * Model name → untrusted repository and replica entry.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export type Catalog = ReadonlyMap<string, CatalogEntry>;

/**
 * A gateway replica's last successful verification.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export interface ReplicaVerification {
  readonly host: string;
  readonly models: readonly string[];
  readonly reference: string;
  readonly pinnedModel: string;
  readonly verification: Verification;
}

/**
 * Configures a {@link GatewayHTTPClient}.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export interface GatewayOptions {
  /** Pins models to repositories. With `pinnedModelsOnly`, only pinned models are served, which requires at least one pin. */
  readonly modelPins?: ReadonlyMap<string, ModelPin>;
  readonly pinnedModelsOnly?: boolean;
  /** The policy for unpinned models; undefined selects the defaults. */
  readonly verifier?: Verifier;
  /** Called with each replica's verification, for pinned and unpinned models. A rejected replica is skipped for the next replica of the model. */
  readonly verificationCheck?: VerificationCheck;
  /** As for {@link RouterOptions.userCacheSecret}. */
  readonly userCacheSecret?: string;
  /** The gateway's base URL; undefined selects Tinfoil's gateway. */
  readonly url?: string;
  /**
   * Read on every request and must return an immutable catalog. Undefined
   * fetches the gateway's catalog when the client is created and refreshes
   * it every 10 seconds while the client is used; a failed refresh keeps the
   * last catalog fetched.
   */
  readonly catalog?: () => Catalog;
  /** Aborts the catalog fetch the factory performs before it returns. */
  readonly signal?: AbortSignal;
}
