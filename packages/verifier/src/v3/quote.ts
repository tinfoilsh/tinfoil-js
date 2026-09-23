// v3 CPU-evidence verification in three phases (Go: verifier/quote/quote.go):
//
//  1. Authenticate: verify the quote's signature chain up to the pinned
//     vendor root, from document-carried collateral only.
//  2. Assemble: resolve the complete policy — every value the quote must
//     attest, as one object. Assembly fails if any entry cannot be resolved.
//  3. Validate: one comparison of the quote against the assembled policy.

import { decodeHex } from "./bytes.js";
import { SEVSNPReportV1Format, TDXQuoteV1Format, type Document } from "./envelope.js";
import { VerificationError } from "./errors.js";
import { SevGuestV2, SnpTdxMultiPlatformV1, TdxGuestV2, type Measurement } from "./measurement.js";
import { PlatformSEVSNP, PlatformTDX, policyFor, type Artifact, type Shape } from "./policy.js";
import { sevAssemble, sevAuthenticate, sevValidate, type SevExpectations, type SevQuote } from "./sev/index.js";
import { tdxAuthenticate, type TdxQuote } from "./tdx/authenticate.js";
import { tdxAssemble, tdxValidate, type CodeRegisters, type TdxExpectations } from "./tdx/expectations.js";

// registerSize is the byte length of every measurement register.
const registerSize = 48;

// QuoteOpts selects the vendor roots and the validity-window clock;
// defaults are the embedded production roots and the current time.
export interface QuoteOpts {
  amdRootPEM?: string;
  intelRootPEM?: string;
  now?: Date;
}

// Authenticated is a signature-verified quote, not yet compared against any
// expected value (Go: quote.Authenticated).
export interface Authenticated {
  // platform is PlatformSEVSNP or PlatformTDX.
  platform: string;
  // identity is the machine identifier from authenticated bytes
  // (SEV CHIP_ID / TDX PPID), lowercase hex.
  identity: string;
  // measurement is the launch measurement (SEV) or MRTD+RTMRs (TDX).
  measurement: Measurement;

  sev?: SevQuote;
  tdx?: TdxQuote;
}

// AssembledPolicy is the complete expected state of a quote, fully resolved
// before validation runs (Go: quote.AssembledPolicy).
export interface AssembledPolicy {
  policyName: string;
  // platformMeasurementName is the resolved TDX platform configuration;
  // empty for SEV-SNP.
  platformMeasurementName: string;

  quote: Authenticated;
  sev?: SevExpectations;
  tdx?: TdxExpectations;
}

function quoteError(message: string): VerificationError {
  return new VerificationError("QUOTE_REJECTED", message);
}

function policyError(message: string): VerificationError {
  return new VerificationError("POLICY_REJECTED", message);
}

// quoteAuthenticate verifies the quote's signature chain up to the pinned
// vendor root, from the document's own endorsement collateral — no network
// fetches (Go: quote.Authenticate). Callers must assemble a policy and
// validate before trusting the platform.
export async function quoteAuthenticate(doc: Document, opts?: QuoteOpts): Promise<Authenticated> {
  switch (doc.cpuEvidence.format) {
    case SEVSNPReportV1Format: {
      const q = await sevAuthenticate(doc, { rootPEM: opts?.amdRootPEM, now: opts?.now });
      return { platform: PlatformSEVSNP, identity: q.identity, measurement: q.measurement, sev: q };
    }
    case TDXQuoteV1Format: {
      const q = await tdxAuthenticate(doc, { rootPEM: opts?.intelRootPEM, now: opts?.now });
      return { platform: PlatformTDX, identity: q.identity, measurement: q.measurement, tdx: q };
    }
    default:
      throw quoteError(`unsupported cpu_evidence format ${JSON.stringify(doc.cpuEvidence.format)}`);
  }
}

// quoteAssemble resolves the complete policy for an authenticated quote from
// its three verified sources: the policy artifact (machine lookup by
// authenticated identity; for TDX, the platform measurement resolved under
// the required VM shape), the code measurement, and the envelope's
// REPORT_DATA. A machine absent from the artifact is not endorsed
// (Go: quote.Assemble).
export function quoteAssemble(
  endorsements: Artifact,
  code: Measurement | undefined,
  shape: Shape | undefined,
  reportData: Uint8Array,
  q: Authenticated,
): AssembledPolicy {
  if (code === undefined) {
    throw policyError("assembling policy: expected code measurement is required");
  }
  if (shape === undefined) {
    throw policyError("assembling policy: the code artifact's VM shape is required");
  }
  const { name, policy: machinePolicy } = policyFor(endorsements, q.identity, q.platform);
  const assembled: AssembledPolicy = { policyName: name, platformMeasurementName: "", quote: q };
  switch (q.platform) {
    case PlatformSEVSNP: {
      const digest = sevLaunchDigest(code);
      assembled.sev = sevAssemble(machinePolicy.sevSnp!, q.sev!, digest, reportData);
      break;
    }
    case PlatformTDX: {
      const registers = tdxCodeRegisters(code);
      const { expectations, name: measurementName } = tdxAssemble(
        endorsements,
        machinePolicy.tdx!,
        shape,
        q.tdx!,
        registers,
        reportData,
      );
      assembled.tdx = expectations;
      assembled.platformMeasurementName = measurementName;
      break;
    }
    default:
      throw policyError(`unsupported platform ${JSON.stringify(q.platform)}`);
  }
  return assembled;
}

// assembledValidate compares the captured quote against the assembled policy
// in a single call: no lookups, no translation (Go: AssembledPolicy.Validate).
export function assembledValidate(p: AssembledPolicy): void {
  switch (p.quote.platform) {
    case PlatformSEVSNP:
      sevValidate(p.sev!, p.quote.sev!);
      break;
    case PlatformTDX:
      tdxValidate(p.tdx!, p.quote.tdx!);
      break;
    default:
      throw policyError(`unsupported platform ${JSON.stringify(p.quote.platform)}`);
  }
}

// assembleAndValidate composes quoteAssemble and assembledValidate; every
// rejection is POLICY_REJECTED.
export function assembleAndValidate(
  endorsements: Artifact,
  code: Measurement | undefined,
  shape: Shape | undefined,
  reportData: Uint8Array,
  auth: Authenticated,
): AssembledPolicy {
  const assembled = quoteAssemble(endorsements, code, shape, reportData, auth);
  assembledValidate(assembled);
  return assembled;
}

// sevLaunchDigest maps the expected code measurement onto the SEV launch
// digest register (Go: sevLaunchDigest).
function sevLaunchDigest(m: Measurement): Uint8Array {
  switch (m.type) {
    case SnpTdxMultiPlatformV1:
      if (m.registers.length !== 3) {
        throw policyError(`multiplatform code measurement carries ${m.registers.length} registers, want 3`);
      }
      return decodeRegister(m.registers[0]);
    case SevGuestV2:
      if (m.registers.length !== 1) {
        throw policyError(`SEV code measurement carries ${m.registers.length} registers, want 1`);
      }
      return decodeRegister(m.registers[0]);
    default:
      throw policyError(`unsupported code measurement type ${JSON.stringify(m.type)} for SEV-SNP`);
  }
}

// tdxCodeRegisters maps the expected code measurement onto the TDX workload
// registers (Go: tdxCodeRegisters).
function tdxCodeRegisters(m: Measurement): CodeRegisters {
  switch (m.type) {
    case SnpTdxMultiPlatformV1:
      // Registers are [snp_measurement, rtmr1, rtmr2]; RTMR3 is never
      // measured and must be zero.
      if (m.registers.length !== 3) {
        throw policyError(`multiplatform code measurement carries ${m.registers.length} registers, want 3`);
      }
      return {
        rtmr1: decodeRegister(m.registers[1]),
        rtmr2: decodeRegister(m.registers[2]),
        rtmr3: new Uint8Array(registerSize),
      };
    case TdxGuestV2:
      // Registers are [mrtd, rtmr0, rtmr1, rtmr2, rtmr3].
      if (m.registers.length !== 5) {
        throw policyError(`TDX code measurement carries ${m.registers.length} registers, want 5`);
      }
      return {
        rtmr1: decodeRegister(m.registers[2]),
        rtmr2: decodeRegister(m.registers[3]),
        rtmr3: decodeRegister(m.registers[4]),
      };
    default:
      throw policyError(`unsupported code measurement type ${JSON.stringify(m.type)} for TDX`);
  }
}

// decodeRegister decodes a 48-byte hex measurement register.
function decodeRegister(hexValue: string): Uint8Array {
  let b: Uint8Array;
  try {
    b = decodeHex(hexValue);
  } catch (err) {
    throw policyError(`code measurement register is not hex: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (b.length !== registerSize) {
    throw policyError(`code measurement register must be ${registerSize} bytes, got ${b.length}`);
  }
  return b;
}
