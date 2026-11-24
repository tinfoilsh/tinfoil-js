/**
 * One enclave and the policy its attestation is verified against. An Enclave
 * keeps no state; {@link VerifiedEnclave} caches what it verifies.
 *
 * A verification is fresh evidence: a document fetched with a fresh nonce,
 * verified under the policy, endorsing the keys a transport binds traffic to,
 * inside its freshness window, and accepted by the caller's verification
 * check. A network or attestation failure is retried once after a second; a
 * configuration error or a rejection by the verification check is not.
 * Each verification resolves to the verifier's report, whose verified facts
 * are set.
 */
import {
  CRYPTO_MATERIAL_ID_HPKE,
  CRYPTO_MATERIAL_ID_TLS,
  KEY_SPKI_FP_SHA256_V1_FORMAT,
  KEY_X25519_HPKE_V1_FORMAT,
  randomNonce,
  UsageError,
  Verifier,
  type Pin,
  type VerificationReport,
  type VerifiedFacts,
} from "@tinfoilsh/verifier";
import { AttestationError, ConfigurationError, messageOf, NetworkError, stripCategory, TinfoilError, withMessage } from "../errors.js";
import type { AttestationFetcher, Fetch, OnVerification, VerificationAttempt, VerificationCheck } from "../options.js";
import { fetchDocument, fetchDocumentWith } from "./fetch.js";

export const VERIFICATION_RETRIES = 1;
export const VERIFICATION_RETRY_DELAY_MS = 1_000;

/** The message of a verification whose witnesses no longer authorize requests. */
export const FRESHNESS_EXPIRED = "attestation freshness witnesses have expired; retry verification with fresh evidence";

/** A report of a verification that passed, so that its verified facts are set. */
export type VerifiedReport = VerificationReport & { readonly verifiedFacts: VerifiedFacts };

/** Describes an {@link Enclave}. */
export interface EnclaveConfig {
  /** The enclave, a host with an optional port. */
  readonly host: string;
  /** When set, a host that fetches attestation from the enclave on the client's behalf. */
  readonly relay?: string;
  /** What the enclave is verified against. */
  readonly pin: Pin;
  /** The policy, which several enclaves can share; undefined selects the defaults. */
  readonly verifier?: Verifier;
  /** Called with each verification that passes the verifier; a throw rejects it without a retry. */
  readonly verificationCheck?: VerificationCheck;
  /** Called with the outcome of each attempt to verify the enclave, through {@link Enclave.notify}. */
  readonly onVerification?: OnVerification;
  /** How each attestation document is obtained; undefined fetches it directly, or through `relay`. */
  readonly fetchAttestation?: AttestationFetcher;
  /** Seams for tests: the fetch used for documents, the clock, the nonce source and the retry delay. */
  readonly fetch?: Fetch;
  readonly clock?: () => Date;
  readonly nonce?: () => Uint8Array;
  readonly sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

/** A verification check's rejection: a decision about the evidence, so it is not retried. */
export class RejectedError extends AttestationError {
  constructor(host: string, cause: unknown) {
    super(`verification check rejected ${host}: ${messageOf(cause)}`, { cause });
    this.name = "RejectedError";
  }
}

export class Enclave {
  readonly #host: string;
  readonly #relay: string | undefined;
  readonly #pin: Required<Pin>;
  readonly #verifier: Verifier;
  readonly #check: VerificationCheck | undefined;
  readonly #onVerification: OnVerification | undefined;
  readonly #fetch: Fetch;
  readonly #fetchAttestation: AttestationFetcher | undefined;
  readonly #clock: () => Date;
  readonly #nonce: () => Uint8Array;
  readonly #sleep: (ms: number, signal?: AbortSignal) => Promise<void>;

  private constructor(config: EnclaveConfig, verifier: Verifier) {
    this.#host = config.host;
    this.#relay = config.relay;
    this.#pin = Object.freeze({ repo: config.pin.repo ?? "", project: config.pin.project ?? "" });
    this.#verifier = verifier;
    this.#check = config.verificationCheck;
    this.#onVerification = config.onVerification;
    this.#fetch = config.fetch ?? ((input, init) => fetch(input, init));
    this.#fetchAttestation = config.fetchAttestation;
    this.#clock = config.clock ?? (() => new Date());
    this.#nonce = config.nonce ?? randomNonce;
    this.#sleep = config.sleep ?? sleep;
  }

  /** Checks the pin against the verifier's rules; no network I/O. */
  static async create(config: EnclaveConfig): Promise<Enclave> {
    if (config.host === "") throw new ConfigurationError("enclave host is required");
    try {
      const verifier = config.verifier ?? (await Verifier.create());
      verifier.checkPinVerifiability(config.pin);
      return new Enclave(config, verifier);
    } catch (err) {
      throw fromVerify(err);
    }
  }

  host(): string {
    return this.#host;
  }

  /** The pin the enclave is verified against; an unset part is "". */
  pin(): Required<Pin> {
    return this.#pin;
  }

  /** The verification policy, which several enclaves can share. */
  verifier(): Verifier {
    return this.#verifier;
  }

  /**
   * Fetches and verifies the enclave's attestation, retrying once after a
   * network or attestation failure. Each attempt that fails and is retried
   * is passed to `retried` before the retry starts; the outcome of the last
   * attempt is the result.
   */
  verify(signal?: AbortSignal, retried?: (err: TinfoilError) => void): Promise<VerifiedReport> {
    return this.#verify(VERIFICATION_RETRIES, signal, retried);
  }

  /** Verifies like {@link verify} but doesn't retry, so a caller trying several enclaves moves on quickly. */
  verifyOnce(signal?: AbortSignal): Promise<VerifiedReport> {
    return this.#verify(0, signal, undefined);
  }

  /**
   * Reports the outcome of an attempt to verify the enclave to the
   * `onVerification` callback, if there is one. The caller passes a
   * frozen attempt whose report no one else holds. A throw from the callback
   * doesn't change the outcome or reach the caller: it is rethrown
   * asynchronously, to the runtime's handler for uncaught errors.
   */
  notify(attempt: VerificationAttempt): void {
    if (this.#onVerification === undefined) return;
    try {
      this.#onVerification(this.#host, attempt);
    } catch (err) {
      queueMicrotask(() => {
        throw err;
      });
    }
  }

  async #verify(retries: number, signal: AbortSignal | undefined, retried: ((err: TinfoilError) => void) | undefined): Promise<VerifiedReport> {
    let firstErr: TinfoilError | undefined;
    for (let attempt = 0; ; attempt++) {
      signal?.throwIfAborted();
      let err: TinfoilError | undefined;
      try {
        const verified = await this.#fetchVerification(signal);
        this.#checkFreshness(verified.verifiedFacts);
        await this.#checkVerification(verified.verifiedFacts);
        // The verification check can outlast the freshness window; a retry fetches fresh evidence.
        this.#checkFreshness(verified.verifiedFacts);
        return verified;
      } catch (e) {
        // A caller that gave up gets its own reason back, not the failure its abort caused.
        if (signal?.aborted) throw signal.reason;
        err = e instanceof TinfoilError ? e : new AttestationError(messageOf(e), { cause: e });
      }
      if (attempt === retries || !retryable(err)) {
        if (firstErr !== undefined) {
          err = joined(err, firstErr);
        }
        throw err;
      }
      firstErr = err;
      retried?.(err);
      await this.#sleep(VERIFICATION_RETRY_DELAY_MS, signal);
    }
  }

  async #fetchVerification(signal: AbortSignal | undefined): Promise<VerifiedReport> {
    const nonce = this.#nonce();
    const doc =
      this.#fetchAttestation === undefined
        ? await fetchDocument(this.#host, this.#relay, nonce, this.#fetch, signal)
        : await fetchDocumentWith(this.#fetchAttestation, this.#host, nonce, signal);
    let report: VerificationReport;
    try {
      report = await this.#verifier.verifyV3At(doc, nonce, this.#pin, this.#clock());
    } catch (err) {
      throw fromVerify(err);
    }
    if (report.verifiedFacts === undefined) throw new AttestationError("verification passed without verified facts");
    validateTransportKeys(report.verifiedFacts);
    return report as VerifiedReport;
  }

  #checkFreshness(v: VerifiedFacts): void {
    const expiresAt = v.freshnessExpiresAt;
    if (expiresAt === undefined || !(this.#clock().getTime() < expiresAt.getTime())) {
      throw new AttestationError(FRESHNESS_EXPIRED);
    }
  }

  async #checkVerification(v: VerifiedFacts): Promise<void> {
    if (this.#check === undefined) return;
    try {
      await this.#check(v);
    } catch (err) {
      throw new RejectedError(this.#host, err);
    }
  }
}

/** Whether verified facts valid at `now` are still inside their freshness window. */
export function freshAt(v: VerifiedFacts, now: Date): boolean {
  const expiresAt = v.freshnessExpiresAt;
  return expiresAt !== undefined && now.getTime() < expiresAt.getTime();
}

/**
 * A verifier error in the client's categories, by its outermost type: a
 * usage error is the caller's configuration error, and anything else the
 * verifier rejects is an attestation failure. The verifier error remains the
 * cause, so that a rejection's report stays reachable from it. A usage
 * error is recognized by `instanceof` first and by its name otherwise, so
 * one thrown by another loaded copy of the verifier package
 * (a second version installed alongside, or a bundle that failed to
 * dedupe), whose class is a different object, is still the caller's error.
 */
export function fromVerify(err: unknown): TinfoilError {
  if (err instanceof TinfoilError) return err;
  if (err instanceof UsageError || isUsageErrorByName(err)) return new ConfigurationError(messageOf(err), { cause: err });
  return new AttestationError(messageOf(err), { cause: err });
}

/** Whether `err` presents as the verifier's usage error without sharing its class. */
function isUsageErrorByName(err: unknown): boolean {
  return err instanceof Error && err.name === "UsageError";
}

/** Requires the keys a transport binds traffic to: the TLS key, and the HPKE key when the document endorses one. */
function validateTransportKeys(v: VerifiedFacts): void {
  keyFormat(v, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT);
  if (v.tlsPublicKeyFP === undefined) throw new AttestationError(`document endorses no ${JSON.stringify(CRYPTO_MATERIAL_ID_TLS)} key`);
  keyFormat(v, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT);
}

/** Rejects an endorsed `id` key whose format is not `format`. */
function keyFormat(v: VerifiedFacts, id: string, format: string): void {
  for (const item of v.cryptoMaterial) {
    if (item.id === id && item.format !== format) {
      throw new AttestationError(`crypto_material item ${JSON.stringify(id)} has format ${JSON.stringify(item.format)}, want ${JSON.stringify(format)}`);
    }
  }
}

/** A network or attestation failure is retried; a configuration error or a verification check's rejection is not. */
function retryable(err: TinfoilError): boolean {
  if (err instanceof RejectedError || err instanceof ConfigurationError) return false;
  return err instanceof NetworkError || err instanceof AttestationError;
}

/** The terminal failure, keeping the first attempt's as diagnostics. */
function joined(last: TinfoilError, first: TinfoilError): TinfoilError {
  return withMessage(last, `${stripCategory(last)} (first attempt: ${first.message})`);
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
