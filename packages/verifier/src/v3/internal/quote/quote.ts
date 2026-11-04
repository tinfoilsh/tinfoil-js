/**
 * CPU quotes, in three phases: authenticate the hardware signature chain to
 * the vendor root from document-carried collateral alone; assemble the
 * complete expected state from reference values, caller pins and the
 * document's bound REPORT_DATA; validate the quote against it in one
 * comparison.
 */
import { SEV_SNP_REPORT_V1_FORMAT, TDX_QUOTE_V1_FORMAT, type CpuEndorsements, type CpuEvidence, type Document } from "../../document/document.js";
import { cloneMeasurement, type Expected, type Measurement } from "../../measurement.js";
import { PLATFORM_SEV_SNP, PLATFORM_TDX, type Artifact, type Platform, type Policy } from "../policy/artifact.js";
import { bytesEqual } from "../x509/certificate.js";
import { resolveConfig, type ConfigReferenceValues } from "./config.js";
import { resolveLegacy, type LegacyReferenceValues } from "./legacy.js";
import { applyPins, complete, resolvePolicy } from "./resolve.js";
import { assembleSev, authenticateSev, validateSev, type SevExpectations, type SevQuote } from "./sev/authenticate.js";
import { assembleTdx, authenticateTdx, validateTdx, type TdxExpectations, type TdxQuote } from "./tdx/authenticate.js";

export { applyPins, complete, resolvePolicy };

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

/** The fully resolved expected state, ready to validate. It captures the quote it was assembled for. */
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
    case SEV_SNP_REPORT_V1_FORMAT: {
      // A document is single-request: missing collateral rejects rather than
      // being fetched.
      if (endorsements.amdVcek === undefined) throw new Error("no amd-vcek endorsement collateral for the cpu");
      if (endorsements.amdCrl === undefined) throw new Error("no amd-crl endorsement collateral for the cpu");
      const q = await authenticateSev(
        {
          report: evidence.report,
          vcekDer: endorsements.amdVcek.vcekDer,
          certChainPem: endorsements.amdVcek.certChainPem,
          crlDer: endorsements.amdCrl.crlDer,
        },
        now,
        { dangerousTestOnlyRoot: opts?.dangerousTestOnlyRoots?.amd },
      );
      return {
        platform: PLATFORM_SEV_SNP,
        identity: q.identity,
        measurement: cloneMeasurement(q.measurement),
        evidence: { format: evidence.format, report: evidence.report.slice() },
        sev: q,
      };
    }
    case TDX_QUOTE_V1_FORMAT: {
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
 *
 * `doc` must come from `document.parse`, so its expected REPORT_DATA was
 * recomputed from the caller's nonce, and `q` must be the quote
 * authenticated from that document's own CPU evidence: a quote is never
 * appraised against another document's challenge.
 */
export async function assemble(doc: Document, refs: ReferenceValues, pins: Expected | undefined, q: Authenticated): Promise<AssembledPolicy> {
  return assembleWith(refs, pins, reportDataOf(doc, q), q);
}

function reportDataOf(doc: Document, q: Authenticated): Uint8Array {
  // Both checks bind the quote to the caller's challenge. The verifier never
  // fails them, so failing one is a caller bug, and the document is rejected.
  const reportData = doc.expectedReportData();
  if (reportData === undefined) throw new Error("a document checked by document.parse is required");
  const evidence = doc.cpuEvidence();
  if (evidence.format !== q.evidence.format || !bytesEqual(evidence.report, q.evidence.report)) {
    throw new Error("authenticated quote is not this document's CPU evidence");
  }
  return reportData;
}

/** `assemble` against an explicit REPORT_DATA. */
export async function assembleWith(refs: ReferenceValues, pins: Expected | undefined, reportData: Uint8Array, q: Authenticated): Promise<AssembledPolicy> {
  const resolved = refs.kind === "legacy" ? resolveLegacy(refs, q, pins) : resolveConfig(refs, q, pins);
  const expected = complete(resolved.expected);
  const assembled = {
    codeMeasurement: resolved.code,
    policyName: resolved.policyName,
    platformMeasurementName: resolved.platformMeasurementName,
    quote: q,
  };
  switch (expected.platform) {
    case PLATFORM_SEV_SNP: {
      if (q.platform !== PLATFORM_SEV_SNP || q.sev === undefined) {
        throw new Error(`expected an SEV-SNP measurement for a ${q.platform} quote`);
      }
      const policy = resolved.policy.sevSnp;
      if (policy === undefined) throw new Error("resolved policy has no sev_snp block");
      return { ...assembled, sev: assembleSev(policy, q.sev, expected.launch, reportData, resolved.hostData) };
    }
    case PLATFORM_TDX: {
      if (q.platform !== PLATFORM_TDX || q.tdx === undefined) {
        throw new Error(`expected a TDX measurement for a ${q.platform} quote`);
      }
      const policy = resolved.policy.tdx;
      if (policy === undefined) throw new Error("resolved policy has no tdx block");
      return { ...assembled, tdx: assembleTdx(policy, q.tdx, expected, reportData, resolved.configId) };
    }
  }
}

/** Validates the authenticated quote against the assembled expectations in one comparison. */
export async function validate(p: AssembledPolicy): Promise<void> {
  switch (p.quote.platform) {
    case PLATFORM_SEV_SNP:
      if (p.sev === undefined || p.quote.sev === undefined) throw new Error("assembled policy has no SEV-SNP expectations");
      validateSev(p.sev, p.quote.sev);
      return;
    case PLATFORM_TDX:
      if (p.tdx === undefined || p.quote.tdx === undefined) throw new Error("assembled policy has no TDX expectations");
      validateTdx(p.tdx, p.quote.tdx);
      return;
    default:
      throw new Error(`unsupported platform ${JSON.stringify(p.quote.platform)}`);
  }
}

/** Re-exported for callers that build reference values. */
export type { Artifact };
