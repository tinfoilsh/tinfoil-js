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
 *
 * Every attempt to verify, whether it passes or fails, becomes the last
 * verification as soon as its outcome is decided, and is reported to the
 * enclave's `onVerification` callback once the refresh that made it is
 * over, so that the callback can call the cache again without waiting for
 * that refresh. An attempt that a close cuts short has no outcome: it is
 * neither recorded nor reported, and only its callers see the close.
 */
import type { VerifiedFacts } from "@tinfoilsh/verifier";
import { AttestationError, wrapAttestation, type TinfoilError } from "../errors.js";
import type { VerificationAttempt } from "../options.js";
import { closedError } from "./dispose.js";
import { Enclave, FRESHNESS_EXPIRED, freshAt, type VerifiedReport } from "./enclave.js";

/** One successful verification, its report, and what the transport bound to its keys. */
export interface State<T> {
  readonly report: VerifiedReport;
  readonly bound: T;
}

/** How a refresh verifies the enclave, passing each failed attempt that it retries to `retried`. */
type Verify = (e: Enclave, retried: (err: TinfoilError) => void) => Promise<VerifiedReport>;

interface Entry<T> extends State<T> {
  rejected: boolean;
  /** Whether the binding has already been released, as a discarded state's is. */
  released: boolean;
}

export class VerifiedEnclave<T = void> {
  readonly #enclave: Enclave;
  readonly #bind: (v: VerifiedFacts) => T | Promise<T>;
  readonly #release: (bound: T) => void;
  readonly #clock: () => Date;
  #current: Entry<T> | undefined;
  /** The outcome of the most recent attempt, or undefined before the first. */
  #last: VerificationAttempt | undefined;
  /** The refresh in flight, shared by every caller that needs one. */
  #refreshing: Promise<void> | undefined;
  #closed = false;

  /**
   * `bind` makes what the transport ties to verified facts' keys; a cache
   * that only caches verifications binds `() => undefined`. `release` is
   * called with a binding once its state is replaced or found expired, so
   * connections tied to retired keys are closed.
   */
  constructor(enclave: Enclave, bind: (v: VerifiedFacts) => T | Promise<T>, clock: () => Date = () => new Date(), release: (bound: T) => void = () => {}) {
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
    return this.#verified(signal, false, (e, retried) => e.verify(undefined, retried));
  }

  /** Verifies again even if the current verification is still valid. */
  reverify(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, true, (e, retried) => e.verify(undefined, retried));
  }

  /** Verifies like {@link reverify} but without the retry, so a caller trying several enclaves moves on quickly. */
  verifyOnce(signal?: AbortSignal): Promise<State<T>> {
    return this.#verified(signal, true, (e) => e.verifyOnce());
  }

  /**
   * The outcome of the most recent attempt, without I/O or a freshness
   * check, or undefined before the first: its report, a copy that the
   * caller may keep, or the error that the attempt failed with.
   */
  lastVerification(): VerificationAttempt | undefined {
    return copyAttempt(this.#last);
  }

  /** Marks the state a request was sent under rejected, so the next request verifies again; a replaced state leaves the current one valid. */
  invalidate(state: State<T>): void {
    if (this.#current !== undefined && this.#current.report === state.report) this.#current.rejected = true;
  }

  /**
   * Releases the current binding and verifies no more: every later call
   * for a state rejects as closed, and a refresh in flight releases what it
   * binds instead of publishing it. The last attempt stays readable.
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
    return !entry.rejected && freshAt(entry.report.verifiedFacts, this.#clock());
  }

  async #verified(signal: AbortSignal | undefined, force: boolean, verify: Verify): Promise<State<T>> {
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
      const refresh = (this.#refreshing ??= this.#shared(verify));
      await raceWithSignal(refresh, signal);
      // A request can reject the new state before this caller wakes, so the
      // loop checks the current state again rather than trust the refresh.
      force = false;
    }
  }

  /**
   * A refresh that concurrent callers share. Once it is over, it is
   * forgotten first, and then each of its attempts is reported to the
   * enclave's callback, so that a callback that verifies again starts a
   * refresh of its own rather than waiting for this one.
   */
  #shared(verify: Verify): Promise<void> {
    const attempts: VerificationAttempt[] = [];
    return this.#refresh(verify, attempts).finally(() => {
      this.#refreshing = undefined;
      for (const attempt of attempts) {
        this.#enclave.notify(attempt.report?.clone(), attempt.error);
      }
    });
  }

  /**
   * Verifies the enclave and publishes the result as the current state. An
   * attestation failure discards the state that the refresh was replacing;
   * a network failure, a configuration error or a close leaves it as it is.
   * Each attempt, retried or final, becomes the last one as soon as its
   * outcome is decided, and is added to `attempts`. A verification that
   * passes after the cache was closed is abandoned before it is published,
   * so it has no outcome: it is neither recorded nor reported, and its
   * callers get the close. A failure that the attempt reached on its own is
   * an outcome, even after a close.
   */
  async #refresh(verify: Verify, attempts: VerificationAttempt[]): Promise<void> {
    const replacing = this.#current;
    const record = (attempt: VerificationAttempt): void => {
      this.#last = attempt;
      attempts.push(attempt);
    };
    let report: VerifiedReport | undefined;
    try {
      report = await this.#publish(verify, (error) => record({ error }));
    } catch (err) {
      // Every failure is reported in a category, and the error recorded is the one thrown.
      const error = wrapAttestation(err);
      if (error instanceof AttestationError) this.#discard(replacing);
      record({ error });
      throw error;
    }
    if (report === undefined) throw closedError();
    record({ report });
  }

  /** Verifies and publishes the new state, returning its report, or undefined when a close abandoned it. */
  async #publish(verify: Verify, retried: (err: TinfoilError) => void): Promise<VerifiedReport | undefined> {
    const report = await verify(this.#enclave, retried);
    const bound = await this.#bind(report.verifiedFacts);
    const entry: Entry<T> = { report, bound, rejected: false, released: false };
    // A close during the refresh already released the current binding; this one is not published.
    if (this.#closed) {
      this.#release(bound);
      return undefined;
    }
    // Binding can outlast freshness.
    if (!this.#valid(entry)) {
      this.#release(bound);
      throw new AttestationError(FRESHNESS_EXPIRED);
    }
    // What the replaced state holds is tied to its keys.
    if (this.#current !== undefined) this.#releaseEntry(this.#current);
    this.#current = entry;
    return report;
  }
}

/** A copy of `attempt` that the caller may keep: its report is cloned, and its error is the same one. */
function copyAttempt(attempt: VerificationAttempt | undefined): VerificationAttempt | undefined {
  if (attempt === undefined) return undefined;
  return Object.freeze(attempt.error === undefined ? { report: attempt.report.clone() } : { error: attempt.error });
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
