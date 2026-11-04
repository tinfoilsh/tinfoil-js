/**
 * The verification cache a transport sits on. It verifies the enclave on
 * first use, and again when the verification expires or is invalidated, and
 * publishes each verification together with whatever a transport binds to
 * its keys, so a request never sends under keys other than those of the
 * verification it checked. Concurrent callers share one verification,
 * including its failure. No network I/O happens until the first request or
 * `ensureVerified`.
 */
import type { Verification } from "@tinfoilsh/verifier/v3";
import { AttestationError } from "../errors.js";
import { Enclave, FRESHNESS_EXPIRED, freshAt } from "./enclave.js";

/** One successful verification and what the transport bound to its keys. */
export interface State<T> {
  readonly verification: Verification;
  readonly bound: T;
}

interface Entry<T> extends State<T> {
  rejected: boolean;
}

export class VerifiedEnclave<T = void> {
  readonly #enclave: Enclave;
  readonly #bind: (v: Verification) => T | Promise<T>;
  readonly #clock: () => Date;
  #current: Entry<T> | undefined;
  /** The refresh in flight, shared by every caller that needs one. */
  #refreshing: Promise<void> | undefined;

  /**
   * `bind` makes what the transport ties to a verification's keys; a cache
   * that only caches verifications binds `() => undefined`.
   */
  constructor(enclave: Enclave, bind: (v: Verification) => T | Promise<T>, clock: () => Date = () => new Date()) {
    this.#enclave = enclave;
    this.#bind = bind;
    this.#clock = clock;
  }

  enclave(): Enclave {
    return this.#enclave;
  }

  /** A state valid now, verifying first only if the current one has expired or been invalidated. */
  ensureVerified(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, false, (e, s) => e.verify(s));
  }

  /** Verifies again even if the current verification is still valid. */
  reverify(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, true, (e, s) => e.verify(s));
  }

  /** Verifies like {@link reverify} but without the retry, so a caller trying several enclaves moves on quickly. */
  verifyOnce(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, true, (e, s) => e.verifyOnce(s));
  }

  /** The last successful verification without checking it, or undefined before the first. */
  current(): Verification | undefined {
    return this.#current?.verification;
  }

  /** Marks the state a request was sent under rejected, so the next request verifies again; a replaced state leaves the current one valid. */
  invalidate(state: State<T>): void {
    if (this.#current !== undefined && this.#current.verification === state.verification) this.#current.rejected = true;
  }

  #valid(entry: Entry<T>): boolean {
    return !entry.rejected && freshAt(entry.verification, this.#clock());
  }

  async #verified(signal: AbortSignal | undefined, force: boolean, verify: (e: Enclave, signal?: AbortSignal) => Promise<Verification>): Promise<State<T>> {
    for (;;) {
      signal?.throwIfAborted();
      const current = this.#current;
      if (current !== undefined && this.#valid(current) && !force) return current;
      // A caller's cancellation does not abort a refresh other callers need,
      // so the refresh runs without the signal; the caller stops waiting.
      const refresh = (this.#refreshing ??= this.#refresh(verify).finally(() => {
        this.#refreshing = undefined;
      }));
      await raceWithSignal(refresh, signal);
      // A request can reject the new state before this caller wakes, so the
      // loop checks the current state again rather than trust the refresh.
      force = false;
    }
  }

  /** Verifies the enclave and publishes the result as the current state. */
  async #refresh(verify: (e: Enclave) => Promise<Verification>): Promise<void> {
    const verification = await verify(this.#enclave);
    const bound = await this.#bind(verification);
    const entry: Entry<T> = { verification, bound, rejected: false };
    // Binding can outlast freshness.
    if (!this.#valid(entry)) throw new AttestationError(FRESHNESS_EXPIRED);
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
