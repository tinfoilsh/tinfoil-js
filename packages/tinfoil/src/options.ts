/**
 * The options the clients take, and the types their facts are reported in.
 * Every client checks its options before any network I/O, so a misconfigured
 * client fails at creation rather than on its first request.
 */
import type { Policy, Verification } from "@tinfoilsh/verifier";

export type { ArtifactTrust, EmbeddedArtifacts, EndorsedArtifacts, Policy } from "@tinfoilsh/verifier";
import type { ClientOptions as WsClientOptions } from "ws";

/**
 * A client's `fetch`: the call signature of the global `fetch`, bound to the
 * client's attested transport, so it can be handed to any library that takes
 * a `fetch`. It is declared from the global so it follows the `fetch` of the
 * caller's own typings; a function with this signature is assignable to
 * `typeof fetch` wherever that is a plain function type.
 */
export type Fetch = (...args: Parameters<typeof globalThis.fetch>) => ReturnType<typeof globalThis.fetch>;

/**
 * How a client protects its traffic to an enclave: {@link TLS} or
 * {@link EHBP}, told apart by `kind`. Undefined selects the platform's
 * default: `{ kind: "tls" }` on Node, Bun 1.4.0 or later and Deno 2.8.0 or
 * later, which check a connection before they send over it, and
 * `{ kind: "ehbp" }` in browsers and on an older Bun or Deno. `{ kind: "tls" }`
 * is a {@link ConfigurationError} where the platform can't pin a connection,
 * and so is an unknown `kind`.
 */
export type Transport = TLS | EHBP;

/**
 * Pins each connection to the attested TLS key. It protects the whole
 * request and response, and needs a direct connection to the enclave, so it
 * takes no URL: requests go to the enclave's own HTTPS origin.
 */
export interface TLS {
  readonly kind: "tls";
}

/**
 * Seals request and response bodies to the attested HPKE key, so that they
 * stay private through a proxy. The method, URL and headers aren't sealed,
 * and neither is a request without a body or its response. It refuses
 * protocol upgrades and CONNECT tunnels, because nothing after the handshake
 * would be sealed.
 */
export interface EHBP {
  readonly kind: "ehbp";
  /**
   * A proxy that forwards requests to the enclave, and that requests are
   * sent to; undefined or "" sends them directly to the enclave. Its path, if
   * any, is where the proxy is mounted, not the API path: an OpenAI client
   * joins its API path under it. Requests to the proxy carry
   * `X-Tinfoil-Enclave-Url` so that it can forward them. The proxy must use
   * HTTPS, since EHBP doesn't seal headers such as the API key; `http://` is
   * accepted only when its host is localhost or a loopback IP address. A URL
   * with a username or password, a query or a fragment, even an empty one,
   * is a {@link ConfigurationError}, and so is an enclave client's proxy on
   * the enclave's own origin, which is no proxy: leave it unset to connect
   * directly.
   */
  readonly proxyURL?: string;
  /**
   * The network implementation that sends the sealed requests, for a native
   * HTTP bridge or a trusted relay. It receives each request after its body
   * is sealed, and the response that it returns is opened by the client; a
   * request without a body passes through it unsealed, as EHBP leaves it.
   * The method, URL and headers aren't sealed, so a relay sees them, the API
   * key included. Attestation documents and the router list are still
   * fetched with the runtime's fetch. Undefined selects the runtime's fetch.
   */
  readonly fetch?: Fetch;
}

/**
 * Obtains the attestation document of an enclave for a challenge nonce, in
 * place of the client's direct fetch from the enclave; {@link attestationRelay}
 * returns one that fetches through a relay. `host` is the enclave's host,
 * with an optional port, and `nonce` is the fresh 32-byte challenge that the
 * document must answer. The client verifies whatever it returns as it
 * verifies a document that it fetched itself, so a fetcher isn't trusted: it
 * can make verification fail, but it can't make an enclave pass that
 * wouldn't pass otherwise.
 *
 * A client calls it for every verification: when it is created, whenever it
 * verifies again after an expiry or a key rotation, and, on the router
 * route, for each router that discovery tries and for the fallback.
 * `signal` ends after 30 seconds. A verification can serve many requests,
 * so it isn't any one caller's: a caller's cancellation ends only that
 * caller's wait, and the fetch goes on until it settles or the 30 seconds
 * pass. The client stops waiting when `signal` ends, even if the fetcher
 * ignores it. A thrown
 * error is reported as a {@link NetworkError} that wraps it, unless it
 * already is an SDK error. It may be called concurrently.
 */
export type AttestationFetcher = (host: string, nonce: Uint8Array, options: { readonly signal: AbortSignal }) => Promise<Uint8Array>;

/**
 * Obtains the candidate routers for router discovery, in place of the
 * client's fetch from `https://atc.tinfoil.sh/routers`; {@link routerListRelay}
 * returns one that fetches through a relay. The list isn't trusted: it only
 * proposes hosts, and discovery verifies each one before it uses it, tries
 * them for at most 30 seconds in all, and falls back to inference.tinfoil.sh
 * when none passes. A thrown error, or a result that isn't an array of
 * strings, counts as an empty list.
 *
 * An attestation document doesn't name the host that serves it, so the list
 * source is trusted not to name a host that would relay another router's
 * attestation: with EHBP, such a host would receive the request headers,
 * including the API key, although not the sealed bodies.
 *
 * `signal` ends when the caller's signal does, or after 30 seconds.
 */
export type RouterListFetcher = (options: { readonly signal: AbortSignal }) => Promise<readonly string[]>;

/**
 * Called with each verification that passes the verifier, before the client
 * uses the enclave's keys: when the client is created and whenever it
 * verifies again. Throw to reject the enclave; verification then fails with
 * an {@link AttestationError} wrapping the thrown value and isn't retried.
 * Requests wait while it runs, so keep it fast; it may run concurrently.
 */
export type VerificationCheck = (verification: Verification) => void | Promise<void>;

/**
 * The options of one call on a client, such as `ensureVerified` or
 * `reverify`. Any setting a call takes later is a field here rather than a
 * parameter, so callers that pass none are unaffected.
 */
export interface CallOptions {
  /**
   * Stops the call waiting and rejects it with the signal's reason. A
   * verification or catalog fetch other callers share keeps running.
   */
  readonly signal?: AbortSignal;
}

/**
 * The `ws` client settings a pinned connection owns, so a caller's values
 * for them are dropped: those that choose the peer, check its certificate,
 * or shape the handshake's headers (`headers` itself, `origin`, which is a
 * header, and `finishRequest`, which hands the caller the request) and
 * subprotocol.
 */
export type ReservedWsOption =
  | "agent"
  | "createConnection"
  | "followRedirects"
  | "session"
  | "socket"
  | "servername"
  | "pskCallback"
  | "checkServerIdentity"
  | "rejectUnauthorized"
  | "ca"
  | "headers"
  | "origin"
  | "finishRequest"
  | "protocol";

/** The `ws` client settings a caller may set: the library's own, less the {@link ReservedWsOption}s. */
export type WsOptions = Readonly<Omit<WsClientOptions, ReservedWsOption>>;

/** Configures a WebSocket opened by {@link createWebSocket}. */
export interface WebSocketOptions {
  /** The subprotocols offered in the handshake. */
  readonly protocols?: string | readonly string[];
  /** Headers sent with the handshake, such as `Authorization`. */
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * Settings for the `ws` client on Node, such as `perMessageDeflate` or
   * `maxPayload`. Settings that would change which peer is connected to, how
   * its certificate is checked, or the handshake's headers (`headers`,
   * `origin` and `finishRequest`) and `protocol` are ignored; the
   * handshake's headers come from the top-level `headers`.
   * Bun's WebSocket takes no such settings, so they are ignored there.
   */
  readonly wsOptions?: WsOptions;
  /** Aborts the verification the call performs before connecting. */
  readonly signal?: AbortSignal;
}

/** Configures a realtime session opened by {@link createRealtimeWebSocket}. */
export interface RealtimeOptions {
  /** The realtime model to start a session with. */
  readonly model: string;
  /** As {@link WebSocketOptions.wsOptions}. */
  readonly wsOptions?: WsOptions;
  /** Aborts the verification the call performs before connecting. */
  readonly signal?: AbortSignal;
}

/** How long a listener added to a {@link PinnedWebSocket} stays. */
export interface WebSocketListenerOptions {
  /** Removes the listener after its first call. */
  readonly once?: boolean;
  /**
   * Removes the listener when the signal aborts. A signal that has already
   * aborted adds no listener at all.
   */
  readonly signal?: AbortSignal;
}

/**
 * A WebSocket whose connection is pinned to the attested TLS key, in the
 * CONNECTING state when returned. A pin failure surfaces as an `error`
 * event whose error is an {@link AttestationError}; a failure of the
 * runtime's own certificate check surfaces as that runtime's error. Either
 * makes the client verify again before its next connection. The socket
 * supports the standard event-target API, with the `once` and `signal`
 * listener options on every runtime; on Node it is a `ws` WebSocket and
 * also supports that library's `on` listeners.
 */
export interface PinnedWebSocket {
  readonly readyState: number;
  readonly url: string;
  readonly protocol: string;
  send(data: string | ArrayBufferLike | ArrayBufferView): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "open", listener: (event: unknown) => void, options?: WebSocketListenerOptions): void;
  addEventListener(type: "message", listener: (event: { readonly data: unknown }) => void, options?: WebSocketListenerOptions): void;
  addEventListener(type: "error", listener: (event: { readonly error?: unknown; readonly message?: string }) => void, options?: WebSocketListenerOptions): void;
  addEventListener(type: "close", listener: (event: { readonly code: number; readonly reason: string }) => void, options?: WebSocketListenerOptions): void;
  removeEventListener(type: "open", listener: (event: unknown) => void): void;
  removeEventListener(type: "message", listener: (event: { readonly data: unknown }) => void): void;
  removeEventListener(type: "error", listener: (event: { readonly error?: unknown; readonly message?: string }) => void): void;
  removeEventListener(type: "close", listener: (event: { readonly code: number; readonly reason: string }) => void): void;
}

/**
 * Configures an {@link EnclaveHTTPClient}. It has no prompt-cache option:
 * an enclave client sends request bodies as they are, and never adds or
 * changes a `user_cache_secret` member. A caller that points one at
 * Tinfoil's router and wants a scoped prompt cache sets that member in each
 * request body.
 */
export interface EnclaveOptions {
  /**
   * How requests to the enclave are protected: {@link TLS} or {@link EHBP}.
   * Undefined selects the platform's default: `{ kind: "tls" }` on Node,
   * Bun 1.4.0 or later and Deno 2.8.0 or later, which check a connection
   * before they send over it, and `{ kind: "ehbp" }` in browsers and on an
   * older Bun or Deno. `{ kind: "tls" }` is a {@link ConfigurationError}
   * where the platform can't pin a connection: in a browser, and on a Bun
   * older than 1.4.0 or a Deno older than 2.8.0.
   */
  readonly transport?: Transport;
  /**
   * The verification policy, as plain data; undefined selects the defaults.
   * The client builds its verifier from the trust argument and this policy,
   * so an invalid field is a {@link ConfigurationError}.
   */
  readonly policy?: Policy;
  readonly verificationCheck?: VerificationCheck;
  /**
   * How the client obtains each attestation document; undefined fetches it
   * directly from the enclave. Use {@link attestationRelay} to fetch through
   * a relay, or a function of your own; see {@link AttestationFetcher}.
   */
  readonly fetchAttestation?: AttestationFetcher;
  /** Aborts the verification the factory performs before it returns. */
  readonly signal?: AbortSignal;
}

/** Configures a {@link RouterHTTPClient}. */
export interface RouterOptions {
  /**
   * How requests to the router are protected: {@link TLS} or {@link EHBP}.
   * An EHBP proxy forwards requests to the router that discovery chooses.
   * Undefined selects the platform's default: `{ kind: "tls" }` on Node,
   * Bun 1.4.0 or later and Deno 2.8.0 or later, which check a connection
   * before they send over it, and `{ kind: "ehbp" }` in browsers and on an
   * older Bun or Deno. `{ kind: "tls" }` is a {@link ConfigurationError}
   * where the platform can't pin a connection: in a browser, and on a Bun
   * older than 1.4.0 or a Deno older than 2.8.0.
   */
  readonly transport?: Transport;
  /**
   * The verification policy, as plain data; undefined selects the defaults.
   * The router's config trust is fixed to its repository.
   */
  readonly policy?: Policy;
  /**
   * Called for each router tried during discovery and whenever the client
   * verifies again. A rejection during discovery moves on to the next router;
   * otherwise it fails verification as for an enclave client.
   */
  readonly verificationCheck?: VerificationCheck;
  /**
   * How the client obtains each attestation document, for every router that
   * discovery tries, the fallback and every later verification; undefined
   * fetches it directly from the router. See {@link AttestationFetcher}.
   */
  readonly fetchAttestation?: AttestationFetcher;
  /**
   * How the client obtains its list of candidate routers; undefined fetches
   * Tinfoil's list. Use {@link routerListRelay} to fetch through a relay, or
   * a function of your own; see {@link RouterListFetcher}. Discovery runs
   * whatever the list's source.
   */
  readonly fetchRouterList?: RouterListFetcher;
  /**
   * The default prompt-cache scope. A non-empty `user_cache_secret` string
   * in a request's JSON body overrides it. Undefined or empty selects a
   * random secret that is generated in memory once for the current runtime
   * (the process, or the page in a browser) and shared by every client in
   * it, so prompt-cache hits aren't shared across processes; pass a secret here to keep one that is stable across
   * processes or machines. The SDK reads no environment variable or file
   * for it. Use an opaque random value, not a raw user ID or API key.
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
  /**
   * The pin's policy: undefined inherits {@link GatewayOptions.policy}, and a
   * policy replaces it entirely, so an unset field takes the SDK's default
   * rather than the gateway's.
   */
  readonly policy?: Policy;
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
  /** The policy for unpinned models, and for pinned models whose pin has none; undefined selects the defaults. */
  readonly policy?: Policy;
  /** Called with each replica's verification, for pinned and unpinned models. A rejected replica is skipped for the next replica of the model. */
  readonly verificationCheck?: VerificationCheck;
  /** As for {@link RouterOptions.userCacheSecret}. */
  readonly userCacheSecret?: string;
  /** The gateway's base URL, made to end with `/`; undefined selects Tinfoil's gateway. A query string or fragment is a {@link ConfigurationError}. */
  readonly url?: string;
  /**
   * Read on every request and must return an immutable catalog. Undefined
   * fetches the gateway's catalog when the client is created and refreshes
   * it every 10 seconds while the client is used; a failed refresh keeps the
   * last catalog fetched.
   */
  readonly catalog?: () => Catalog;
  /**
   * As {@link EHBP.fetch}: the network implementation that sends the
   * client's sealed requests to the gateway, which always uses EHBP. The
   * catalog and attestation documents are still fetched with the runtime's
   * fetch.
   */
  readonly fetch?: Fetch;
  /** Aborts the catalog fetch the factory performs before it returns. */
  readonly signal?: AbortSignal;
}
