/**
 * CPU quotes: authenticating the hardware signature chain to the vendor
 * root, then assembling and validating the expected state from reference
 * values.
 */
import { SEV_SNP_REPORT_V1_FORMAT, TDX_QUOTE_V1_FORMAT, type CpuEndorsements, type CpuEvidence, type Document } from "../../document/document.js";
import { notImplemented } from "../../errors.js";
import type { Expected, Measurement } from "../../measurement.js";
import { PLATFORM_TDX, type Artifact, type Platform, type Policy } from "../policy/artifact.js";
import type { ConfigReferenceValues } from "./config.js";
import type { LegacyReferenceValues } from "./legacy.js";
import type { SevExpectations, SevQuote } from "./sev/authenticate.js";
import { authenticateTdx, type TdxExpectations, type TdxQuote } from "./tdx/authenticate.js";

/** Vendor trust anchors that replace the embedded production roots. Test-only. */
export interface VendorRoots {
  /** AMD KDS chain, ASK then ARK, PEM. */
  readonly amd?: Uint8Array;
  /** Intel SGX root CA, PEM. */
  readonly intel?: Uint8Array;
}

export interface QuoteOptions {
  /** Only the conformance adapter sets this; it is not reachable through the package's public API. */
  readonly dangerousTestOnlyRoots?: VendorRoots;
}

/** A quote whose signature chain was authenticated to the vendor root. */
export interface Authenticated {
  readonly platform: Platform;
  /** CHIP_ID (SEV-SNP) or PPID (TDX), lowercase hex. */
  readonly identity: string;
  /** The authenticated launch measurement, or MRTD and RTMRs. */
  readonly measurement: Measurement;
  /** The evidence that was authenticated, so assembly can check it is the document's. */
  readonly evidence: CpuEvidence;
  readonly sev?: SevQuote;
  readonly tdx?: TdxQuote;
}

/** Reference values the quote is compared against: a code release, or a config-pinned runtime. */
export type ReferenceValues = LegacyReferenceValues | ConfigReferenceValues;

/** Values resolved from reference values for one authenticated quote. */
export interface ResolvedValues {
  readonly policy: Policy;
  readonly policyName: string;
  readonly platformMeasurementName: string;
  /** The registers the reference fixes. */
  readonly code: Expected;
  /** Every register, after pins fill what the reference leaves open. */
  readonly expected: Expected;
  /** The 32-byte SEV-SNP HOST_DATA expectation, carried into the assembled expectations. */
  readonly hostData: Uint8Array;
  /** TDX MRCONFIGID. */
  readonly configId: Uint8Array;
}

/** The fully resolved expected state, ready to validate. */
export interface AssembledPolicy {
  readonly codeMeasurement: Expected;
  readonly policyName: string;
  readonly platformMeasurementName: string;
  /** @internal */
  readonly quote: Authenticated;
  readonly sev?: SevExpectations;
  readonly tdx?: TdxExpectations;
}

/**
 * Authenticates the CPU evidence's signature chain to the vendor root,
 * checking collateral validity at `now`. Requires the VCEK and CRL for an
 * SEV-SNP report, or PCS collateral for a TDX quote.
 */
export async function authenticate(evidence: CpuEvidence, endorsements: CpuEndorsements, now: Date, opts?: QuoteOptions): Promise<Authenticated> {
  switch (evidence.format) {
    case SEV_SNP_REPORT_V1_FORMAT:
      return notImplemented("quote.authenticate (sev-snp)");
    case TDX_QUOTE_V1_FORMAT: {
      // Collateral comes with the document; a missing entry rejects rather than being fetched.
      if (endorsements.intelPcs === undefined) throw new Error("no intel-pcs endorsement collateral for the cpu");
      const intel = opts?.dangerousTestOnlyRoots?.intel;
      const q = await authenticateTdx(
        { quote: evidence.report, pcs: endorsements.intelPcs.responses },
        now,
        intel === undefined ? undefined : { dangerousTestOnlyRoot: intel },
      );
      return {
        platform: PLATFORM_TDX,
        identity: q.identity,
        measurement: q.measurement,
        evidence: { format: evidence.format, report: evidence.report.slice() },
        tdx: q,
      };
    }
    default:
      throw new Error(`unsupported cpu_evidence format ${JSON.stringify(evidence.format)}`);
  }
}

/**
 * Resolves the reference values for the quote, applies the caller's pins
 * (filling open registers; conflicting with a fixed one, or pinning the
 * other platform, rejects), requires every register to be set, and builds
 * the platform's expectations with the document's bound REPORT_DATA.
 */
export async function assemble(doc: Document, refs: ReferenceValues, pins: Expected | undefined, q: Authenticated): Promise<AssembledPolicy> {
  return notImplemented("quote.assemble");
}

/** Validates the authenticated quote against the assembled expectations. */
export async function validate(p: AssembledPolicy): Promise<void> {
  return notImplemented("quote.validate");
}

/** Looks up the machine's policy in the endorsements artifact for the quote's platform and identity. */
export function resolvePolicy(endorsements: Artifact, q: Authenticated): { policy: Policy; policyName: string } {
  return notImplemented("quote.resolvePolicy");
}

/** Fills registers the reference leaves open from `pins`; a pin that conflicts with a fixed register, or targets the other platform, rejects. */
export function applyPins(code: Expected, platform: Platform, pins: Expected | undefined): Expected {
  return notImplemented("quote.applyPins");
}

/** Every register must be set; returns them as a measurement. */
export function complete(e: Expected): Measurement {
  return notImplemented("quote.complete");
}
