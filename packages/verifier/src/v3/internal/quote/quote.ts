import type { CpuEndorsements, CpuEvidence } from "../../document/document.js";
import { NotImplementedError } from "../../errors.js";
import type { Measurement } from "../../measurement.js";
import type { Platform } from "../policy/artifact.js";

/** Vendor trust anchors that replace the embedded production roots. Test-only. */
export interface VendorRoots {
  /** AMD KDS chain, ASK then ARK, PEM. */
  readonly amd?: Uint8Array;
  /** Intel SGX root CA, PEM. */
  readonly intel?: Uint8Array;
}

export interface QuoteOptions {
  /**
   * Replaces the embedded vendor roots. Only the conformance adapter sets
   * this; it is not reachable through the package's public API.
   */
  readonly dangerousTestOnlyRoots?: VendorRoots;
}

/** A quote whose signature chain was authenticated to the vendor root. */
export interface Authenticated {
  readonly platform: Platform;
  /** The authenticated launch measurement (SEV) or MRTD and RTMRs (TDX). */
  readonly measurement: Measurement;
}

/**
 * Authenticates the CPU quote's signature chain to the vendor root, checking
 * collateral validity at `now`. Does not compare against any policy.
 */
export async function authenticate(
  evidence: CpuEvidence,
  endorsements: CpuEndorsements,
  now: Date,
  opts?: QuoteOptions,
): Promise<Authenticated> {
  void evidence;
  void endorsements;
  void now;
  void opts;
  throw new NotImplementedError("quote.authenticate");
}
