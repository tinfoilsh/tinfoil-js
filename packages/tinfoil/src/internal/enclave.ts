/**
 * One enclave and the policy its attestation is verified against. An Enclave
 * keeps no state; {@link VerifiedEnclave} caches what it verifies.
 *
 * A verification is fresh evidence: a document fetched with a fresh nonce,
 * verified under the policy, endorsing the keys a transport binds traffic to,
 * inside its freshness window, and accepted by the caller's verification
 * check. A network or attestation failure is retried once after a second; a
 * configuration error or a rejection by the verification check is not.
 */
import {
  CRYPTO_MATERIAL_ID_HPKE,
  CRYPTO_MATERIAL_ID_TLS,
  KEY_SPKI_FP_SHA256_V1_FORMAT,
  KEY_X25519_HPKE_V1_FORMAT,
  randomNonce,
  UsageError,
  Verifier,
  type Verification,
} from "@tinfoilsh/verifier";
import { AttestationError, ConfigurationError, messageOf, NetworkError, stripCategory, TinfoilError, withMessage } from "../errors.js";
import type { Fetch, VerificationCheck } from "../options.js";
import { fetchDocument } from "./fetch.js";

export const VERIFICATION_RETRIES = 1;
export const VERIFICATION_RETRY_DELAY_MS = 1_000;

/** The message of a verification whose witnesses no longer authorize requests. */
export const FRESHNESS_EXPIRED = "attestation freshness witnesses have expired; retry verification with fresh evidence";

/** Describes an {@link Enclave}. */
export interface EnclaveConfig {
  /** The enclave, a host with an optional port. */
  readonly host: string;
  /** When set, a host that fetches attestation from the enclave on the client's behalf. */
  readonly relay?: string;
  /** Pins a repository or registry project, `org/project[@revision][@sha256:digest]`; empty accepts configs the verifier authorizes. */
  readonly repo: string;
  /** The policy, which several enclaves can share; undefined selects the defaults. */
  readonly verifier?: Verifier;
  /** Called with each verification that passes the verifier; a throw rejects it without a retry. */
  readonly verificationCheck?: VerificationCheck;
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
  readonly #repo: string;
  readonly #verifier: Verifier;
  readonly #check: VerificationCheck | undefined;
  readonly #fetch: Fetch;
  readonly #clock: () => Date;
  readonly #nonce: () => Uint8Array;
  readonly #sleep: (ms: number, signal?: AbortSignal) => Promise<void>;

  private constructor(config: EnclaveConfig, verifier: Verifier) {
    this.#host = config.host;
    this.#relay = config.relay;
    this.#repo = config.repo;
    this.#verifier = verifier;
    this.#check = config.verificationCheck;
    this.#fetch = config.fetch ?? ((input, init) => fetch(input, init));
    this.#clock = config.clock ?? (() => new Date());
    this.#nonce = config.nonce ?? randomNonce;
    this.#sleep = config.sleep ?? sleep;
  }

  /** Checks the repository pin against the verifier's rules; no network I/O. */
  static async create(config: EnclaveConfig): Promise<Enclave> {
    if (config.host === "") throw new ConfigurationError("enclave host is required");
    try {
      const verifier = config.verifier ?? (await Verifier.create());
      verifier.checkRepoVerifiability(config.repo);
      return new Enclave(config, verifier);
    } catch (err) {
      throw fromVerify(err);
    }
  }

  host(): string {
    return this.#host;
  }

  /** The trusted repository or registry reference, including version and digest pins. */
  repo(): string {
    return this.#repo;
  }

  /** The verification policy, which several enclaves can share. */
  verifier(): Verifier {
    return this.#verifier;
  }

  /** Fetches and verifies the enclave's attestation, retrying once after a network or attestation failure. */
  verify(signal?: AbortSignal): Promise<Verification> {
    return this.#verify(VERIFICATION_RETRIES, signal);
  }

  /** Verifies like {@link verify} but doesn't retry, so a caller trying several enclaves moves on quickly. */
  verifyOnce(signal?: AbortSignal): Promise<Verification> {
    return this.#verify(0, signal);
  }

  async #verify(retries: number, signal: AbortSignal | undefined): Promise<Verification> {
    let firstErr: TinfoilError | undefined;
    for (let attempt = 0; ; attempt++) {
      signal?.throwIfAborted();
      let err: TinfoilError | undefined;
      try {
        const verified = await this.#fetchVerification(signal);
        this.#checkFreshness(verified);
        await this.#checkVerification(verified);
        // The verification check can outlast the freshness window; a retry fetches fresh evidence.
        this.#checkFreshness(verified);
        return verified;
      } catch (e) {
        if (signal?.aborted) throw e;
        err = e instanceof TinfoilError ? e : new AttestationError(messageOf(e), { cause: e });
      }
      if (attempt === retries || !retryable(err)) {
        if (firstErr !== undefined) {
          err = joined(err, firstErr);
        }
        throw err;
      }
      firstErr = err;
      await this.#sleep(VERIFICATION_RETRY_DELAY_MS, signal);
    }
  }

  async #fetchVerification(signal: AbortSignal | undefined): Promise<Verification> {
    const nonce = this.#nonce();
    const doc = await fetchDocument(this.#host, this.#relay, nonce, this.#fetch, signal);
    let verified: Verification;
    try {
      verified = await this.#verifier.verifyV3At(doc, nonce, this.#repo, this.#clock());
    } catch (err) {
      throw fromVerify(err);
    }
    validateTransportKeys(verified);
    return verified;
  }

  #checkFreshness(v: Verification): void {
    const expiresAt = v.freshnessExpiresAt();
    if (expiresAt === undefined || !(this.#clock().getTime() < expiresAt.getTime())) {
      throw new AttestationError(FRESHNESS_EXPIRED);
    }
  }

  async #checkVerification(v: Verification): Promise<void> {
    if (this.#check === undefined) return;
    try {
      await this.#check(v);
    } catch (err) {
      throw new RejectedError(this.#host, err);
    }
  }
}

/** Whether a verification valid at `now` is still inside its freshness window. */
export function freshAt(v: Verification, now: Date): boolean {
  const expiresAt = v.freshnessExpiresAt();
  return expiresAt !== undefined && now.getTime() < expiresAt.getTime();
}

/**
 * A verifier error in the client's categories, by its outermost type: a
 * usage error is the caller's configuration error, and anything else the
 * verifier rejects is an attestation failure. The verifier error remains the
 * cause.
 */
export function fromVerify(err: unknown): TinfoilError {
  if (err instanceof TinfoilError) return err;
  if (err instanceof UsageError) return new ConfigurationError(err.message, { cause: err });
  return new AttestationError(messageOf(err), { cause: err });
}

/** Requires the keys a transport binds traffic to: the TLS key, and the HPKE key when the document endorses one. */
function validateTransportKeys(v: Verification): void {
  keyFormat(v, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT);
  if (v.tlsPublicKeyFP() === undefined) throw new AttestationError(`document endorses no ${JSON.stringify(CRYPTO_MATERIAL_ID_TLS)} key`);
  keyFormat(v, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT);
}

/** Rejects an endorsed `id` key whose format is not `format`. */
function keyFormat(v: Verification, id: string, format: string): void {
  for (const item of v.cryptoMaterial()) {
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
