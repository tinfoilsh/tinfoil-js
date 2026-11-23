/**
 * The verification cache a transport sits on. It verifies the enclave on
 * first use, and again when the verification expires or is invalidated, and
 * publishes each verification together with whatever a transport binds to
 * its keys, so a request never sends under keys other than those of the
 * verification it checked. Concurrent callers share one verification,
 * including its failure. A re-verification that fails with an
 * {@link AttestationError} discards the verification that it was replacing,
 * even one that is still fresh, so the next request verifies again; any
 * other failure leaves a fresh verification in use. No network I/O happens
 * until the first request or `ensureVerified`.
 */
import type { Verification } from "@tinfoilsh/verifier";
import { AttestationError } from "../errors.js";
import { closedError } from "./dispose.js";
import { Enclave, FRESHNESS_EXPIRED, freshAt } from "./enclave.js";

/** One successful verification and what the transport bound to its keys. */
export interface State<T> {
  readonly verification: Verification;
  readonly bound: T;
}

interface Entry<T> extends State<T> {
  rejected: boolean;
  /** Whether the binding has already been released, as a discarded state's is. */
  released: boolean;
}

export class VerifiedEnclave<T = void> {
  readonly #enclave: Enclave;
  readonly #bind: (v: Verification) => T | Promise<T>;
  readonly #release: (bound: T) => void;
  readonly #clock: () => Date;
  #current: Entry<T> | undefined;
  /** The refresh in flight, shared by every caller that needs one. */
  #refreshing: Promise<void> | undefined;
  #closed = false;

  /**
   * `bind` makes what the transport ties to a verification's keys; a cache
   * that only caches verifications binds `() => undefined`. `release` is
   * called with a binding once its state is replaced or found expired, so
   * connections tied to retired keys are closed.
   */
  constructor(enclave: Enclave, bind: (v: Verification) => T | Promise<T>, clock: () => Date = () => new Date(), release: (bound: T) => void = () => {}) {
    this.#enclave = enclave;
    this.#bind = bind;
    this.#clock = clock;
    this.#release = release;
  }

  enclave(): Enclave {
    return this.#enclave;
  }

  /** A state valid now, verifying first only if the current one has expired or been invalidated. */
  ensureVerified(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, false, (e) => e.verify());
  }

  /** Verifies again even if the current verification is still valid. */
  reverify(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, true, (e) => e.verify());
  }

  /** Verifies like {@link reverify} but without the retry, so a caller trying several enclaves moves on quickly. */
  verifyOnce(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, true, (e) => e.verifyOnce());
  }

  /** The last successful verification without checking it, or undefined before the first. */
  current(): Verification | undefined {
    return this.#current?.verification;
  }

  /** Marks the state a request was sent under rejected, so the next request verifies again; a replaced state leaves the current one valid. */
  invalidate(state: State<T>): void {
    if (this.#current !== undefined && this.#current.verification === state.verification) this.#current.rejected = true;
  }

  /**
   * Releases the current binding and verifies no more: every later call
   * for a state rejects as closed, and a refresh in flight releases what it
   * binds instead of publishing it. The last verification stays readable.
   * Closing again does nothing.
   */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#current !== undefined) this.#releaseEntry(this.#current);
  }

  #releaseEntry(entry: Entry<T>): void {
    if (entry.released) return;
    entry.released = true;
    this.#release(entry.bound);
  }

  /**
   * Discards `replaced` after a re-verification of it failed with an
   * attestation error: no request is sent under it again, and what its
   * binding holds idle (pooled connections tied to its keys) is released
   * now. A newer state that has been published since is kept.
   */
  #discard(replaced: Entry<T> | undefined): void {
    if (replaced === undefined || this.#current !== replaced) return;
    replaced.rejected = true;
    this.#releaseEntry(replaced);
  }

  #valid(entry: Entry<T>): boolean {
    return !entry.rejected && freshAt(entry.verification, this.#clock());
  }

  async #verified(signal: AbortSignal | undefined, force: boolean, verify: (e: Enclave) => Promise<Verification>): Promise<State<T>> {
    for (;;) {
      if (this.#closed) throw closedError();
      signal?.throwIfAborted();
      const current = this.#current;
      if (current !== undefined && this.#valid(current) && !force) return current;
      // A caller's cancellation does not abort a refresh other callers need,
      // so the refresh runs without the signal; the caller stops waiting.
      // That holds for a one-shot probe too: its fetch is bounded by its
      // own timeout, and a probe that joined a refresh can't abort it from
      // under the callers that share it.
      const refresh = (this.#refreshing ??= this.#refresh(verify).finally(() => {
        this.#refreshing = undefined;
      }));
      await raceWithSignal(refresh, signal);
      // A request can reject the new state before this caller wakes, so the
      // loop checks the current state again rather than trust the refresh.
      force = false;
    }
  }

  /**
   * Verifies the enclave and publishes the result as the current state. An
   * attestation failure discards the state that the refresh was replacing;
   * a network failure, a configuration error or a close leaves it as it is.
   */
  async #refresh(verify: (e: Enclave) => Promise<Verification>): Promise<void> {
    const replacing = this.#current;
    try {
      await this.#publish(verify);
    } catch (err) {
      if (err instanceof AttestationError) this.#discard(replacing);
      throw err;
    }
  }

  async #publish(verify: (e: Enclave) => Promise<Verification>): Promise<void> {
    const verification = await verify(this.#enclave);
    const bound = await this.#bind(verification);
    const entry: Entry<T> = { verification, bound, rejected: false, released: false };
    // A close during the refresh already released the current binding; this one is not published.
    if (this.#closed) {
      this.#release(bound);
      throw closedError();
    }
    // Binding can outlast freshness.
    if (!this.#valid(entry)) {
      this.#release(bound);
      throw new AttestationError(FRESHNESS_EXPIRED);
    }
    // What the replaced state holds is tied to its keys.
    if (this.#current !== undefined) this.#releaseEntry(this.#current);
    this.#current = entry;
  }
}

/** Resolves or rejects with `promise`, or rejects with the signal's reason as soon as it aborts. */
function raceWithSignal<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}
