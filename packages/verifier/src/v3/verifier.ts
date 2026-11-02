import { NotImplementedError } from "./errors.js";
import type { VendorRoots } from "./internal/quote/quote.js";
import type { Verification } from "./verification.js";

/**
 * Public verifier options.
 * TODO(v3): pinned registers, freshness max age, config authorizer and
 * signing keys, embedded references (tinfoil-go verify/options.go, config.go).
 */
export interface VerifierOptions {}

/**
 * Trust roots that replace the embedded production anchors. Only the
 * conformance adapter passes these, through {@link dangerousTestOnlyVerifier};
 * this module's export is not re-exported from the package entry.
 */
export interface DangerousTestOnlyRoots extends VendorRoots {
  /** Sigstore trusted-root JSON. */
  readonly sigstore?: Uint8Array;
}

/** Verifies v3 attestation documents. */
export class Verifier {
  /** @internal */
  readonly roots: DangerousTestOnlyRoots;

  constructor(options: VerifierOptions = {}) {
    void options;
    this.roots = {};
  }

  /** Verifies a document against `nonce` and the pinned `repo` at the current time. */
  async verifyV3(docBytes: Uint8Array, nonce: Uint8Array, repo: string): Promise<Verification> {
    return this.verifyV3At(docBytes, nonce, repo, new Date());
  }

  /**
   * Like {@link verifyV3}, but appraises collateral validity and freshness at
   * `verificationTime`. One clock pins both.
   */
  async verifyV3At(docBytes: Uint8Array, nonce: Uint8Array, repo: string, verificationTime: Date): Promise<Verification> {
    void docBytes;
    void nonce;
    void repo;
    void verificationTime;
    throw new NotImplementedError("Verifier.verifyV3At");
  }
}

/** Builds a verifier that trusts the injected roots instead of the embedded ones. */
export function dangerousTestOnlyVerifier(roots: DangerousTestOnlyRoots, options: VerifierOptions = {}): Verifier {
  const v = new Verifier(options);
  (v as { roots: DangerousTestOnlyRoots }).roots = roots;
  return v;
}
