/**
 * AMD SEV-SNP attestation reports: the report ABI, the VCEK → ASK → ARK
 * certificate chain, the CRL, and the expectations a policy turns into.
 */
import { notImplemented } from "../../../errors.js";
import type { Register, SevSnpMeasurement } from "../../../measurement.js";
import type { SevSnpPolicy } from "../../policy/sev.js";

export const REPORT_SIZE = 1184;
export const PRODUCT_GENOA = "Genoa";
export const PRODUCT_TURIN = "Turin";
export type ProductLine = typeof PRODUCT_GENOA | typeof PRODUCT_TURIN;

export interface SevOptions {
  /** PEM chain (ASK then ARK) replacing the embedded one for the report's product. Test-only. */
  readonly dangerousTestOnlyRoot?: Uint8Array;
}

/** The inputs an SEV-SNP quote needs: the raw report and its collateral. */
export interface SevEvidence {
  readonly report: Uint8Array;
  readonly vcekDer: Uint8Array;
  /** ASK then ARK. */
  readonly certChainPem: string;
  readonly crlDer: Uint8Array;
}

/** The decoded fields of a report the verifier reads. */
export interface SevReport {
  readonly version: number;
  readonly guestSvn: number;
  readonly policy: bigint;
  readonly familyId: Uint8Array;
  readonly imageId: Uint8Array;
  readonly vmpl: number;
  readonly signatureAlgo: number;
  readonly currentTcb: bigint;
  readonly platformInfo: bigint;
  readonly signerInfo: number;
  readonly reportData: Uint8Array;
  readonly measurement: Register;
  readonly hostData: Uint8Array;
  readonly idKeyDigest: Uint8Array;
  readonly authorKeyDigest: Uint8Array;
  readonly reportId: Uint8Array;
  readonly reportIdMa: Uint8Array;
  readonly reportedTcb: bigint;
  readonly cpuid1Eax: number;
  readonly chipId: Uint8Array;
  readonly committedTcb: bigint;
  readonly currentBuild: number;
  readonly currentMinor: number;
  readonly currentMajor: number;
  readonly committedBuild: number;
  readonly committedMinor: number;
  readonly committedMajor: number;
  readonly launchTcb: bigint;
  readonly launchMitVector: bigint;
  readonly currentMitVector: bigint;
  /** r‖s, little-endian, 72 bytes each. */
  readonly signature: Uint8Array;
}

/** An authenticated report. */
export interface SevQuote {
  /** CHIP_ID, lowercase hex. */
  readonly identity: string;
  readonly measurement: SevSnpMeasurement;
  readonly report: SevReport;
  readonly productLine: ProductLine;
}

/** Decodes the 1184-byte report; a wrong length rejects. */
export function parseReport(bytes: Uint8Array): SevReport {
  return notImplemented("sev.parseReport");
}

/** The product line from the report's CPUID family/model/stepping; only Genoa and Turin are accepted. */
export function productLine(report: SevReport): ProductLine {
  return notImplemented("sev.productLine");
}

/**
 * Authenticates a report: VCEK present; chain PEM holds exactly two
 * certificates; the CRL is valid at `now`; VCEK → ASK → ARK verify to the
 * embedded (or injected) root for the product, with the VCEK not revoked and
 * its TCB extensions equal to the report's; the report signature verifies
 * under the VCEK; the chip id is not masked; the measurement is 48 bytes.
 */
export async function authenticateSev(evidence: SevEvidence, now: Date, opts?: SevOptions): Promise<SevQuote> {
  return notImplemented("sev.authenticateSev");
}

/** Expectations a policy fixes for a report. */
export interface SevExpectations {
  readonly policy: SevSnpPolicy;
  readonly productLine: ProductLine;
  readonly launch: Register;
  readonly reportData: Uint8Array;
  readonly chipId: Uint8Array;
  /** The 32-byte HOST_DATA the report must carry: the policy's, or for a config-pinned runtime the config hash. */
  readonly hostData: Uint8Array;
}

/**
 * Builds expectations from a policy: Genoa policies must omit fmc_spl and
 * iommu_write_safe, Turin policies must set both; versions parse as maj.min.
 * `hostData` is the resolved expectation, since a v2 policy declares none.
 */
export function assembleSev(policy: SevSnpPolicy, q: SevQuote, launch: Register, reportData: Uint8Array, hostData: Uint8Array): SevExpectations {
  return notImplemented("sev.assembleSev");
}

/**
 * Validates the report against the expectations: guest policy and platform
 * info bits exactly, minimum build/version/SVN/TCBs, VMPL, host data, image
 * and family ids, mitigation vectors, measurement, report data and chip id,
 * and that no author key or id block signed the launch.
 */
export function validateSev(e: SevExpectations, q: SevQuote): void {
  return notImplemented("sev.validateSev");
}
