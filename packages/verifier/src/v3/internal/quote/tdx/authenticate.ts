/**
 * Intel TDX quotes (version 4): the quote ABI, the PCK certificate chain,
 * the collateral replayed from captured PCS responses (TCB info, QE
 * identity, CRLs), and the expectations a policy turns into.
 */
import type { PcsResponse } from "../../../document/collateral/tdx.js";
import { notImplemented } from "../../../errors.js";
import type { Register, TdxMeasurement } from "../../../measurement.js";
import type { TdxPolicy } from "../../policy/tdx.js";

export const MR_CONFIG_ID_SIZE = 48;

export interface TdxOptions {
  /** PEM root CA replacing the embedded Intel SGX root. Test-only. */
  readonly dangerousTestOnlyRoot?: Uint8Array;
}

export interface TdxEvidence {
  readonly quote: Uint8Array;
  readonly pcs: readonly PcsResponse[];
}

/** The decoded fields of a quote the verifier reads. */
export interface TdxQuoteBody {
  readonly teeTcbSvn: Uint8Array;
  readonly mrSeam: Uint8Array;
  readonly mrSignerSeam: Uint8Array;
  readonly seamAttributes: Uint8Array;
  readonly tdAttributes: Uint8Array;
  readonly xfam: Uint8Array;
  readonly mrTd: Register;
  readonly mrConfigId: Uint8Array;
  readonly mrOwner: Uint8Array;
  readonly mrOwnerConfig: Uint8Array;
  readonly rtmrs: readonly [Register, Register, Register, Register];
  readonly reportData: Uint8Array;
}

export interface TdxQuoteHeader {
  readonly version: number;
  readonly attestationKeyType: number;
  readonly teeType: number;
  readonly qeSvn: Uint8Array;
  readonly pceSvn: Uint8Array;
  readonly qeVendorId: Uint8Array;
  readonly userData: Uint8Array;
}

export interface ParsedQuote {
  readonly header: TdxQuoteHeader;
  readonly body: TdxQuoteBody;
  /** Header and body: the bytes the quote signature covers. */
  readonly signedBytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly attestationKey: Uint8Array;
  /** The QE report, its signature, authentication data, and the PCK chain PEM. */
  readonly qeReport: Uint8Array;
  readonly qeReportSignature: Uint8Array;
  readonly qeAuthData: Uint8Array;
  readonly pckChainPem: string;
}

/** An authenticated quote. */
export interface TdxQuote {
  /** PPID, lowercase hex. */
  readonly identity: string;
  readonly measurement: TdxMeasurement;
  /** The lower of the TCB info's and QE identity's evaluation numbers used. */
  readonly tcbEvaluationDataNumber: bigint;
  readonly quote: ParsedQuote;
}

/** Decodes a version 4 quote with certification data type 5; other versions and types reject. */
export function parseQuote(bytes: Uint8Array): ParsedQuote {
  return notImplemented("tdx.parseQuote");
}

/** MRTD and RTMR0 as lowercase hex, for platform-measurement lookup. */
export function platformMeasurements(q: TdxQuote): { mrtd: string; rtmr0: string } {
  return notImplemented("tdx.platformMeasurements");
}

/**
 * Authenticates a quote: version 4 with zero reserved SVN bytes and no
 * extra bytes; the PCK chain to the embedded (or injected) Intel root with
 * CRLs replayed from the PCS collateral and valid at `now`; TCB info and QE
 * identity replayed from the collateral, signed, issued no later than `now`;
 * the QE report and quote signatures; and the TCB status for the quote's
 * SVNs. The minimum TCB evaluation data number of the collateral used is
 * recorded.
 */
export async function authenticateTdx(evidence: TdxEvidence, now: Date, opts?: TdxOptions): Promise<TdxQuote> {
  return notImplemented("tdx.authenticateTdx");
}

/** Expectations a policy fixes for a quote. */
export interface TdxExpectations {
  readonly policy: TdxPolicy;
  readonly measurement: TdxMeasurement;
  readonly reportData: Uint8Array;
  readonly mrConfigId: Uint8Array;
}

export function assembleTdx(policy: TdxPolicy, q: TdxQuote, m: TdxMeasurement, reportData: Uint8Array, mrConfigId: Uint8Array): TdxExpectations {
  return notImplemented("tdx.assembleTdx");
}

/**
 * Validates the quote against the expectations: QE vendor id, minimum TEE
 * TCB SVN, MRSEAM, TD attributes, XFAM, zero MROWNER and MROWNERCONFIG,
 * MRCONFIGID, MRTD and all four RTMRs, report data, and the TCB evaluation
 * data number floor.
 */
export function validateTdx(e: TdxExpectations, q: TdxQuote): void {
  return notImplemented("tdx.validateTdx");
}
