/**
 * The options the clients take, and the types their facts are reported in.
 * Every client checks its options before any network I/O, so a misconfigured
 * client fails at creation rather than on its first request.
 */
import type { Verification, Verifier } from "@tinfoilsh/verifier";
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
 * How a client protects its traffic to an enclave.
 *
 * - `"tls"` pins each connection to the attested TLS key. It protects the
 *   whole request and response and needs a direct connection, so it is the
 *   default where the runtime checks the connection before it sends over
 *   it (Node, and Bun 1.4.0 or later; an older Bun refuses it).
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

/** Configures an {@link EnclaveHTTPClient}. */
export interface EnclaveOptions {
  /** Defaults to `"tls"` on Node and Bun 1.4.0 or later, `"ehbp"` in browsers and on an older Bun, which refuses `"tls"`. */
  readonly transportMode?: TransportMode;
  /**
   * A path on the enclave's own HTTPS origin, or a proxy on another origin,
   * which requires `"ehbp"`. Requests to a proxy carry `X-Tinfoil-Enclave-Url`
   * so it can forward them. A proxy must use HTTPS, since EHBP doesn't seal
   * headers such as the API key; `http://` is accepted only for localhost or
   * a loopback IP address. It is made to end with `/`; a query string or
   * fragment is a {@link ConfigurationError}. For the OpenAI clients this is
   * the API root, used as the OpenAI SDK uses its `baseURL`: nothing is
   * appended, so a proxy that expects the enclave's own paths needs `/v1/`
   * on the end.
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
  /**
   * The network implementation that sends the client's requests in the
   * `"ehbp"` transport mode, for a native HTTP bridge or a trusted relay. It
   * receives each request after its body is sealed, and the response that it
   * returns is opened by the client; a request without a body passes through
   * it unsealed, as the mode leaves it. The method, URL and headers aren't
   * sealed, so a relay sees them, the API key included. Attestation documents
   * are still fetched with the runtime's fetch. Undefined selects the
   * runtime's fetch. Refused with `transportMode: "tls"`, which pins the
   * connection itself and sends nothing through a caller's fetch.
   */
  readonly fetch?: Fetch;
  /** Aborts the verification the factory performs before it returns. */
  readonly signal?: AbortSignal;
}

/** Configures a {@link RouterHTTPClient}. */
export interface RouterOptions {
  /** Defaults to `"tls"` on Node and Bun 1.4.0 or later, `"ehbp"` in browsers and on an older Bun, which refuses `"tls"`. */
  readonly transportMode?: TransportMode;
  /**
   * A proxy that forwards requests to the router discovery chooses, which
   * requires `"ehbp"`: the router isn't known before discovery, so a base URL
   * can't name its origin. Requests carry `X-Tinfoil-Enclave-Url`. The proxy
   * must use HTTPS; `http://` is accepted only for localhost or a loopback IP
   * address. It is made to end with `/`; a query string or fragment is a
   * {@link ConfigurationError}. For the OpenAI clients this is the API root,
   * used as the OpenAI SDK uses its `baseURL`: nothing is appended, so a
   * proxy that expects the enclave's own paths needs `/v1/` on the end.
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
   * The default prompt-cache scope. A non-empty `user_cache_secret` string
   * in a request's JSON body overrides it. Undefined or empty selects a
   * random secret that is generated in memory once per process and shared
   * by every client in it, so prompt-cache hits aren't shared across
   * processes; pass a secret here to keep one that is stable across
   * processes or machines. The SDK reads no environment variable or file
   * for it. Use an opaque random value, not a raw user ID or API key.
   */
  readonly userCacheSecret?: string;
  /**
   * As {@link EnclaveOptions.fetch}: the network implementation that sends
   * the client's sealed requests in the `"ehbp"` transport mode. The router
   * list and attestation documents are still fetched with the runtime's
   * fetch. Refused with `transportMode: "tls"`.
   */
  readonly fetch?: Fetch;
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
   * As {@link EnclaveOptions.fetch}: the network implementation that sends
   * the client's sealed requests to the gateway. The catalog and attestation
   * documents are still fetched with the runtime's fetch.
   */
  readonly fetch?: Fetch;
  /** Aborts the catalog fetch the factory performs before it returns. */
  readonly signal?: AbortSignal;
}
