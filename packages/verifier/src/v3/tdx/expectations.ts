// TDX policy assembly and validation, a 1:1 port of Go
// verifier/quote/tdx/expectations.go plus the go-tdx-guest/validate checks
// the assembled options drive. Every rejection throws
// VerificationError("POLICY_REJECTED").

import { bytesEqual, decodeHex, encodeHex } from "../bytes.js";
import { VerificationError } from "../errors.js";
import {
  decodeHexPolicy,
  resolvePlatformMeasurement,
  validateTDXPolicy,
  type Artifact,
  type Shape,
  type TDXPolicy,
} from "../policy.js";
import type { TdxQuote } from "./authenticate.js";
import type { QuoteV4 } from "./quote.js";

// If bit X is 1 in xfamFixed1, it must be 1 in any xfam (validate.go).
const xfamFixed1 = 0x00000003n;
// If bit X is 0 in xfamFixed0, it must be 0 in any xfam.
const xfamFixed0 = 0x0006dbe7n;
// If bit X is 1 in tdAttributesFixed1, it must be 1 in any tdAttributes.
const tdAttributesFixed1 = 0x0n;
// Supported ATTRIBUTES bits: 0 (DEBUG), 28 (SEPT VE DISABLE), 30 (PKS),
// 63 (PERFMON). If bit X is 0 in tdAttributesFixed0, it must be 0.
const tdAttributesFixed0 = 0x1n | (1n << 28n) | (1n << 30n) | (1n << 63n);

// CodeRegisters are the expected workload registers from code provenance;
// RTMR0 is a platform register and comes from the policy artifact instead.
export interface CodeRegisters {
  rtmr1: Uint8Array;
  rtmr2: Uint8Array;
  rtmr3: Uint8Array;
}

interface ValidateOptions {
  qeVendorID: Uint8Array;
  minimumTeeTcbSvn: Uint8Array;
  mrSeam: Uint8Array;
  tdAttributes: Uint8Array;
  xfam: Uint8Array;
  mrConfigID: Uint8Array;
  mrOwner: Uint8Array;
  mrOwnerConfig: Uint8Array;
  mrTd: Uint8Array;
  rtmrs: Uint8Array[];
  reportData: Uint8Array;
}

// TdxExpectations is the fully translated TDX expected state, resolved at
// assembly so that validation performs no translation and no lookups. The
// collateral floor is separate because it is not a quote field.
export interface TdxExpectations {
  opts: ValidateOptions;
  minimumTCBEvaluationDataNumber: number;
}

function policyError(message: string): VerificationError {
  return new VerificationError("POLICY_REJECTED", message);
}

// tdxAssemble translates a policy block into the complete expected state for
// a quote (Go: tdx.Assemble). The endorsed measurement set is resolved to a
// single MRTD/RTMR0 by the quote's authenticated registers under the
// required VM shape, so a quote outside the endorsed set fails assembly;
// every register comparison then happens inside tdxValidate. The returned
// name is the resolved measurements-map entry.
export function tdxAssemble(
  a: Artifact,
  p: TDXPolicy,
  required: Shape | undefined,
  q: TdxQuote,
  code: CodeRegisters,
  reportData: Uint8Array,
): { expectations: TdxExpectations; name: string } {
  const opts = options(p);
  const body = q.quote.tdQuoteBody;
  if (body.rtmrs.length !== 4) {
    throw policyError("TDX quote body must carry exactly 4 RTMRs");
  }

  const { name, measurement: m } = resolvePlatformMeasurement(a, p, required, encodeHex(body.mrTd), encodeHex(body.rtmrs[0]));
  let mrtd: Uint8Array;
  try {
    mrtd = decodeHex(m.mrtd);
  } catch (err) {
    throw policyError(`platform measurement mrtd is not hex: ${err instanceof Error ? err.message : String(err)}`);
  }
  let rtmr0: Uint8Array;
  try {
    rtmr0 = decodeHex(m.rtmr0);
  } catch (err) {
    throw policyError(`platform measurement rtmr0 is not hex: ${err instanceof Error ? err.message : String(err)}`);
  }
  opts.mrTd = mrtd;
  opts.rtmrs = [rtmr0, code.rtmr1, code.rtmr2, code.rtmr3];
  opts.reportData = reportData;

  return {
    expectations: { opts, minimumTCBEvaluationDataNumber: p.minimumTCBEvaluationDataNumber! },
    name,
  };
}

// tdxValidate compares a quote against the assembled expected state: the
// library validation checks plus the collateral floor (Go:
// Expectations.Validate). It is the only TDX enforcement entry point, so no
// subset of the policy can be applied.
export function tdxValidate(e: TdxExpectations, q: TdxQuote): void {
  validateQuote(q.quote, e.opts);
  if (q.tcbEvaluationDataNumber < e.minimumTCBEvaluationDataNumber) {
    throw policyError(
      `tcbEvaluationDataNumber ${q.tcbEvaluationDataNumber} is below the policy minimum ${e.minimumTCBEvaluationDataNumber}`,
    );
  }
}

// options translates the policy block into library validation options
// (Go: expectations.go options).
function options(p: TDXPolicy): ValidateOptions {
  const invalid = validateTDXPolicy(p);
  if (invalid !== undefined) throw policyError(invalid);
  const qeVendor = decode("qe_vendor_id", p.qeVendorID, 16);
  const teeTcbSvn = decode("minimum_tee_tcb_svn", p.minimumTEETCBSVN, 16);
  const mrSeam = decode("mr_seam", p.mrSeam, 48);
  const tdAttributes = decode("td_attributes", p.tdAttributes, 8);
  const xfam = decode("xfam", p.xfam, 8);

  // MR_CONFIG_ID, MR_OWNER, and MR_OWNER_CONFIG are unconditionally pinned
  // to zero: Tinfoil launches never populate them. The QE and PCE security
  // versions are enforced by quote verification against Intel's signed QE
  // Identity and TCB Info collateral; the library's header minimums compare
  // reserved header bytes (pinned to zero at authentication) and are left
  // unset.
  return {
    qeVendorID: qeVendor,
    minimumTeeTcbSvn: teeTcbSvn,
    mrSeam,
    tdAttributes,
    xfam,
    mrConfigID: new Uint8Array(48),
    mrOwner: new Uint8Array(48),
    mrOwnerConfig: new Uint8Array(48),
    mrTd: new Uint8Array(0),
    rtmrs: [],
    reportData: new Uint8Array(0),
  };
}

function decode(name: string, value: string, wantLen: number): Uint8Array {
  try {
    return decodeHexPolicy(name, value, wantLen);
  } catch (err) {
    throw policyError(err instanceof Error ? err.message : String(err));
  }
}

// validateQuote mirrors tdxvalidate.TdxQuote for quote v4: every check runs
// and all failures are reported (Go: multierr.Combine).
function validateQuote(quote: QuoteV4, opts: ValidateOptions): void {
  const errs: string[] = [];
  exactByteMatch(quote, opts, errs);
  minVersionCheck(quote, opts, errs);
  validateBits("xfam", quote.tdQuoteBody.xfam, xfamFixed1, xfamFixed0, errs);
  validateBits("tdAttributes", quote.tdQuoteBody.tdAttributes, tdAttributesFixed1, tdAttributesFixed0, errs);
  if (errs.length > 0) throw policyError(errs.join("; "));
}

function byteCheck(field: string, given: Uint8Array, required: Uint8Array, errs: string[]): void {
  if (required.length === 0) return;
  if (!bytesEqual(required, given)) {
    errs.push(`quote field ${field} is ${encodeHex(given)}. Expect ${encodeHex(required)}`);
  }
}

function exactByteMatch(quote: QuoteV4, opts: ValidateOptions, errs: string[]): void {
  const body = quote.tdQuoteBody;
  byteCheck("MR_SEAM", body.mrSeam, opts.mrSeam, errs);
  byteCheck("TD_ATTRIBUTES", body.tdAttributes, opts.tdAttributes, errs);
  byteCheck("XFAM", body.xfam, opts.xfam, errs);
  byteCheck("MR_TD", body.mrTd, opts.mrTd, errs);
  byteCheck("MR_CONFIG_ID", body.mrConfigId, opts.mrConfigID, errs);
  byteCheck("MR_OWNER", body.mrOwner, opts.mrOwner, errs);
  byteCheck("MR_OWNER_CONFIG", body.mrOwnerConfig, opts.mrOwnerConfig, errs);
  if (opts.rtmrs.length !== 0) {
    if (opts.rtmrs.length !== 4) {
      errs.push(`RTMR field size(${opts.rtmrs.length}) is not equal to expected size(4)`);
    } else {
      for (let i = 0; i < 4; i++) {
        if (opts.rtmrs[i].length === 0) continue;
        if (opts.rtmrs[i].length !== 48) {
          errs.push(`RTMR[${i}] should be 48 bytes, found ${opts.rtmrs[i].length}`);
          continue;
        }
        byteCheck(`RTMR[${i}]`, body.rtmrs[i], opts.rtmrs[i], errs);
      }
    }
  }
  byteCheck("REPORT_DATA", body.reportData, opts.reportData, errs);
  byteCheck("QE_VENDOR_ID", quote.header.qeVendorId, opts.qeVendorID, errs);
}

// minVersionCheck compares TEE_TCB_SVN component-wise; the QE/PCE header
// minimums are unset (zero) and the reserved header bytes are pinned to
// zero at authentication, so those comparisons are always satisfied.
function minVersionCheck(quote: QuoteV4, opts: ValidateOptions, errs: string[]): void {
  const svn = quote.tdQuoteBody.teeTcbSvn;
  if (opts.minimumTeeTcbSvn.length !== 0) {
    for (let i = 0; i < svn.length; i++) {
      if (svn[i] < opts.minimumTeeTcbSvn[i]) {
        errs.push(`TEE TCB security-version number ${encodeHex(svn)} is less than the required minimum ${encodeHex(opts.minimumTeeTcbSvn)}`);
        break;
      }
    }
  }
}

function leUint64(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

function validateBits(name: string, value: Uint8Array, fixed1: bigint, fixed0: bigint, errs: string[]): void {
  if (value.length === 0) return;
  if (value.length !== 8) {
    errs.push(`${name} size is invalid`);
    return;
  }
  const v = leUint64(value);
  if ((v & fixed1) !== fixed1) {
    errs.push(`unauthorized ${name} 0x${v.toString(16)} as ${name}Fixed1 0x${fixed1.toString(16)} bits are unset`);
  }
  const mask = (1n << 64n) - 1n;
  if ((v & (~fixed0 & mask)) !== 0n) {
    errs.push(`unauthorized ${name} 0x${v.toString(16)} as ${name}Fixed0 0x${fixed0.toString(16)} bits are set`);
  }
}
