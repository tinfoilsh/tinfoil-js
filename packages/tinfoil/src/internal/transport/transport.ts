/**
 * The transport that verifies an enclave and ties requests to the keys of
 * its current verification. A mode protects requests with one verification's
 * keys: TLS pins connections to its TLS key, EHBP seals bodies to its HPKE
 * key. The transport verifies on first use and again when the verification
 * expires or is rejected, does no network I/O before then, and shares one
 * verification among concurrent callers. A key rejection invalidates the
 * verification the request was sent under and is reported through
 * {@link isKeyRejection}; replaying the request is up to the layer above.
 */
import type { Verification } from "@tinfoilsh/verifier";
import { AttestationError, stripCategory } from "../../errors.js";
import type { Fetch, TransportMode } from "../../options.js";
import type { Enclave } from "../enclave.js";
import { VerifiedEnclave, type State } from "../verified.js";
import { requestURL } from "./origin.js";

/** A fetch tied to one verification's keys, and how to release what it holds (connections). */
export interface BoundFetch {
  readonly fetch: Fetch;
  /** Releases everything the binding holds, ending a request still in flight on it: the client is closing. */
  readonly close?: () => void;
  /**
   * Retires the binding once a newer verification replaces it: what it
   * holds idle is released and nothing more is kept, while a request in
   * flight on it, sent under the keys it checked, finishes. Defaults to
   * {@link close}.
   */
  readonly retire?: () => void;
}

/** What a mode inspects about a request before any network I/O. */
export interface RequestShape {
  readonly url: URL;
  readonly method: string;
  readonly headers: Headers;
  /** Whether the call carries a body: in its init, or in a Request input when the init gives none. */
  readonly hasBody: boolean;
}

/** The shape of the request a fetch call describes. */
export function shapeOf(input: string | URL | Request, init?: RequestInit): RequestShape {
  const request = input instanceof Request ? input : undefined;
  const hasBody = init?.body !== undefined ? init.body !== null : request !== undefined && request.body !== null;
  return {
    url: requestURL(input),
    method: (init?.method ?? request?.method ?? "GET").toUpperCase(),
    headers: new Headers(init?.headers ?? request?.headers),
    hasBody,
  };
}

/**
 * The signal a fetch call is under: the init's, or a Request input's own
 * when the init names none. An init signal of null means none, as the
 * Request constructor reads it.
 */
export function signalOf(input: string | URL | Request, init?: RequestInit): AbortSignal | undefined {
  if (init?.signal !== undefined) return init.signal ?? undefined;
  return input instanceof Request ? input.signal : undefined;
}

/**
 * How a mode's fetch handles a redirect: it is handed back to the caller as
 * the response it is, never followed, since following would carry the
 * request wherever the redirect points, past the origin the client is bound
 * to and the keys the mode protects it with. A request that asked for an
 * error on a redirect keeps that.
 */
export function noFollow(redirect: RequestRedirect | undefined): RequestRedirect {
  return redirect === "error" ? "error" : "manual";
}

/**
 * The options a Request carries besides its method, headers, body and
 * signal, for rebuilding it as a new request: a Request can't be rebuilt
 * from itself once its body has been read, so the fields are copied.
 */
export function optionsOf(request: Request): RequestInit {
  const options: RequestInit = {
    credentials: request.credentials,
    redirect: request.redirect,
    cache: request.cache,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
    integrity: request.integrity,
    keepalive: request.keepalive,
  };
  // A navigation mode can't be given to a new request.
  if (request.mode !== "navigate") options.mode = request.mode;
  return options;
}

/** How requests are protected with a verification's keys. */
export interface Mode {
  readonly name: TransportMode;
  /** Rejects, before any network I/O, a request the mode can't protect. */
  validateRequest(request: RequestShape): void;
  /**
   * A fetch tied to `v`'s keys. Its errors meaning the peer doesn't hold
   * those keys, detected before the application processes the request, are
   * {@link PeerLacksKeyError}s.
   */
  bind(v: Verification): BoundFetch | Promise<BoundFetch>;
}

/**
 * A mode's fetch reporting that the peer doesn't hold the keys it was bound
 * to. The transport turns it into a {@link KeyRejectionError} once it has
 * invalidated the verification; a bound fetch used alone can't promise that
 * invalidation, so its errors mustn't make a caller replay.
 */
export class PeerLacksKeyError extends AttestationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PeerLacksKeyError";
  }
}

/** A key rejection whose verification has been invalidated: a caller may replay once if the body allows. */
export class KeyRejectionError extends AttestationError {
  readonly keyRejected = true;

  constructor(cause: PeerLacksKeyError) {
    super(stripCategory(cause), { cause });
    this.name = "KeyRejectionError";
  }
}

/** Whether `err` is a key rejection before application processing, whose verification has already been invalidated. */
export function isKeyRejection(err: unknown): boolean {
  return err instanceof KeyRejectionError && err.keyRejected;
}

export class KeyedTransport {
  readonly #mode: Mode;
  readonly #cache: VerifiedEnclave<BoundFetch>;
  #closed = false;
  /** Bindings retired while the transport was open: a request may still be in flight on one, so each is closed outright when the transport closes. */
  readonly #retired = new Set<BoundFetch>();
  /** Sends a request over a fetch tied to the current verification's keys, verifying first if needed. */
  readonly fetch: Fetch;

  constructor(enclave: Enclave, mode: Mode, clock: () => Date = () => new Date()) {
    this.#mode = mode;
    this.#cache = new VerifiedEnclave<BoundFetch>(enclave, (v) => mode.bind(v), clock, (bound) => this.#release(bound));
    this.fetch = (input, init) => this.#send(input, init);
  }

  /**
   * Releases a binding the cache lets go of. A binding replaced while the
   * transport is open is retired and kept until the transport closes: a
   * request that received its state may still be in flight on it. Once the
   * transport closes, every binding is closed outright.
   */
  #release(bound: BoundFetch): void {
    if (this.#closed || bound.retire === undefined) {
      bound.close?.();
      return;
    }
    bound.retire();
    this.#retired.add(bound);
  }

  async #send(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    // Validate first, so a request the mode can't protect never triggers a verification.
    this.#mode.validateRequest(shapeOf(input, init));
    const state = await this.#cache.ensureVerified(signalOf(input, init));
    try {
      return await state.bound.fetch(input, init);
    } catch (err) {
      if (!(err instanceof PeerLacksKeyError)) throw err;
      // Invalidate the state the request was sent under, not the current
      // one, so a late rejection can't retire a newer verification.
      this.#cache.invalidate(state);
      throw new KeyRejectionError(err);
    }
  }

  mode(): TransportMode {
    return this.#mode.name;
  }

  enclave(): Enclave {
    return this.#cache.enclave();
  }

  /** A verification valid now, verifying first only if needed; success means requests can be sent. */
  async ensureVerified(signal?: AbortSignal): Promise<Verification> {
    return (await this.#cache.ensureVerified(signal)).verification;
  }

  /** Verifies again even if the current verification is still valid. */
  async reverify(signal?: AbortSignal): Promise<Verification> {
    return (await this.#cache.reverify(signal)).verification;
  }

  /** Verifies like {@link reverify} but without the retry. */
  async verifyOnce(signal?: AbortSignal): Promise<Verification> {
    return (await this.#cache.verifyOnce(signal)).verification;
  }

  /** The last successful verification, unchecked. */
  current(): Verification | undefined {
    return this.#cache.current();
  }

  /** The state a request is sent under, for layers that need the bound fetch itself. */
  state(signal?: AbortSignal): Promise<State<BoundFetch>> {
    return this.#cache.ensureVerified(signal);
  }

  /** Marks `state` rejected by the peer, so the next request verifies again; a replaced state leaves the current one valid. */
  invalidate(state: State<BoundFetch>): void {
    this.#cache.invalidate(state);
  }

  /**
   * Releases what the current binding and every retired one hold (the
   * mode's pooled connections, if any, requests in flight on them included)
   * and refuses further use: requests and verification calls reject as
   * closed, while {@link current} still reports the last verification.
   * Closing again does nothing.
   */
  close(): void {
    this.#closed = true;
    this.#cache.close();
    for (const bound of this.#retired) bound.close?.();
    this.#retired.clear();
  }
}
