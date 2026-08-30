// AMD SEV-SNP ATTESTATION_REPORT ABI: the report layout, guest-policy /
// platform-info / signer-info bitfields, CPUID product identity, and TCB
// composition, ported 1:1 from github.com/google/go-sev-guest abi and kds.
// All errors are plain Errors; callers assign the rejection layer.

import { encodeHex } from "../bytes.js";

// ReportSize is the ABI-specified byte size of an SEV-SNP attestation report.
export const ReportSize = 0x4a0;

// SignEcdsaP384Sha384 is the SNP API value for the ECC+SHA signing algorithm.
export const SignEcdsaP384Sha384 = 1;

export const signatureOffset = 0x2a0;
const ecdsaRSSize = 72;

const policyReserved1Bit = 17;

// ReportVersion bounds supported by go-sev-guest.
export const MinSupportedReportVersion = 2;
export const MaxSupportedReportVersion = 5;
const ReportVersion3 = 3;

// Report signer kinds (SIGNER_INFO SIGNING_KEY values).
export const VcekReportSigner = 0;
export const VlekReportSigner = 1;
export const NoneReportSigner = 7;

export function reportSignerString(k: number): string {
  switch (k) {
    case VcekReportSigner:
      return "VCEK";
    case VlekReportSigner:
      return "VLEK";
    case NoneReportSigner:
      return "None";
    default:
      return `UNKNOWN(${k})`;
  }
}

// SnpPolicy represents the bitmask guest policy that governs the VM's
// behavior from launch (Go abi.SnpPolicy).
export interface SnpPolicy {
  abiMinor: number;
  abiMajor: number;
  smt: boolean;
  migrateMA: boolean;
  debug: boolean;
  singleSocket: boolean;
  cxlAllowed: boolean;
  memAES256XTS: boolean;
  raplDis: boolean;
  cipherTextHidingDRAM: boolean;
  pageSwapDisable: boolean;
}

// mbz64 checks a must-be-zero range of a uint64 between bits hi..lo inclusive.
function mbz64(data: bigint, base: string, hi: number, lo: number): void {
  if ((data >> BigInt(lo)) & ((1n << BigInt(hi - lo + 1)) - 1n)) {
    throw new Error(`mbz range ${base}[0x${lo.toString(16)}:0x${hi.toString(16)}] not all zero: ${data.toString(16)}`);
  }
}

const bit = (v: bigint, i: number): boolean => (v & (1n << BigInt(i))) !== 0n;

// parseSnpPolicy interprets the guest policy bitmask (Go abi.ParseSnpPolicy).
export function parseSnpPolicy(guestPolicy: bigint): SnpPolicy {
  if (!bit(guestPolicy, policyReserved1Bit)) {
    throw new Error(`policy[${policyReserved1Bit}] is reserved, must be 1, got 0`);
  }
  mbz64(guestPolicy, "policy", 63, 26);
  return {
    abiMinor: Number(guestPolicy & 0xffn),
    abiMajor: Number((guestPolicy >> 8n) & 0xffn),
    smt: bit(guestPolicy, 16),
    migrateMA: bit(guestPolicy, 18),
    debug: bit(guestPolicy, 19),
    singleSocket: bit(guestPolicy, 20),
    cxlAllowed: bit(guestPolicy, 21),
    memAES256XTS: bit(guestPolicy, 22),
    raplDis: bit(guestPolicy, 23),
    cipherTextHidingDRAM: bit(guestPolicy, 24),
    pageSwapDisable: bit(guestPolicy, 25),
  };
}

// SnpPlatformInfo interprets the PLATFORM_INFO field (Go abi.SnpPlatformInfo).
export interface SnpPlatformInfo {
  smtEnabled: boolean;
  tsmeEnabled: boolean;
  eccEnabled: boolean;
  raplDisabled: boolean;
  ciphertextHidingDRAMEnabled: boolean;
  aliasCheckComplete: boolean;
  // iommuWriteSafe is PLATFORM_INFO bit 6 (Turin). It parses to false for
  // Genoa hardware, which never sets it, so Genoa reports are unaffected.
  iommuWriteSafe: boolean;
  tioEnabled: boolean;
}

// parseSnpPlatformInfo errors on unrecognized bits (Go abi.ParseSnpPlatformInfo,
// bits 0-7).
export function parseSnpPlatformInfo(platformInfo: bigint): SnpPlatformInfo {
  const result: SnpPlatformInfo = {
    smtEnabled: bit(platformInfo, 0),
    tsmeEnabled: bit(platformInfo, 1),
    eccEnabled: bit(platformInfo, 2),
    raplDisabled: bit(platformInfo, 3),
    ciphertextHidingDRAMEnabled: bit(platformInfo, 4),
    aliasCheckComplete: bit(platformInfo, 5),
    iommuWriteSafe: bit(platformInfo, 6),
    tioEnabled: bit(platformInfo, 7),
  };
  if (platformInfo & ~0xffn) {
    throw new Error(`unrecognized platform info bit(s): 0x${platformInfo.toString(16)}`);
  }
  return result;
}

// SignerInfo represents the report signing circumstances (Go abi.SignerInfo).
export interface SignerInfo {
  signingKey: number;
  maskChipKey: boolean;
  authorKeyEn: boolean;
}

// parseSignerInfo interprets report[0x48:0x4C] and errors on non-zero mbz
// fields (Go abi.ParseSignerInfo).
export function parseSignerInfo(signerInfo: number): SignerInfo {
  mbz64(BigInt(signerInfo >>> 0), "data[0x48:0x4C]", 31, 5);
  const signingKey = (signerInfo >>> 2) & 7;
  if (signingKey > VlekReportSigner && signingKey < NoneReportSigner) {
    throw new Error(`signing_key values 2-6 are reserved. Got ${reportSignerString(signingKey)}`);
  }
  return {
    signingKey,
    maskChipKey: (signerInfo & 2) !== 0,
    authorKeyEn: (signerInfo & 1) !== 0,
  };
}

// SevReport is the parsed report (Go proto sevsnp.Report; u64 fields as bigint).
export interface SevReport {
  raw: Uint8Array;
  version: number;
  guestSvn: number;
  policy: bigint;
  familyId: Uint8Array;
  imageId: Uint8Array;
  vmpl: number;
  signatureAlgo: number;
  currentTcb: bigint;
  platformInfo: bigint;
  signerInfo: number;
  reportData: Uint8Array;
  measurement: Uint8Array;
  hostData: Uint8Array;
  idKeyDigest: Uint8Array;
  authorKeyDigest: Uint8Array;
  reportId: Uint8Array;
  reportIdMa: Uint8Array;
  reportedTcb: bigint;
  cpuid1EaxFms: number;
  chipId: Uint8Array;
  committedTcb: bigint;
  currentBuild: number;
  currentMinor: number;
  currentMajor: number;
  committedBuild: number;
  committedMinor: number;
  committedMajor: number;
  launchTcb: bigint;
  launchMitVector: bigint;
  currentMitVector: bigint;
  signature: Uint8Array;
}

function u32(b: Uint8Array, off: number): number {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}

function u64(b: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]);
  return v;
}

function mbz(data: Uint8Array, lo: number, hi: number): void {
  for (let i = lo; i < hi; i++) {
    if (data[i] !== 0) {
      throw new Error(
        `mbz range [0x${lo.toString(16)}:0x${hi.toString(16)}] not all zero: ${encodeHex(data.subarray(lo, hi))}`,
      );
    }
  }
}

// fmsToCpuid1Eax returns the masked CPUID_1_EAX value for the given family,
// model, stepping bytes (Go abi.FmsToCpuid1Eax).
export function fmsToCpuid1Eax(family: number, model: number, stepping: number): number {
  let extendedFamily = 0;
  let familyID = family;
  if (family >= 0xf) {
    extendedFamily = family - 0xf;
    familyID = 0xf;
  }
  const extendedModel = model >> 4;
  const modelID = model & 0xf;
  return ((extendedFamily << 20) | (extendedModel << 16) | (familyID << 8) | (modelID << 4) | (stepping & 0xf)) >>> 0;
}

// fmsFromCpuid1Eax extracts family, model, stepping (Go abi.FmsFromCpuid1Eax).
export function fmsFromCpuid1Eax(eax: number): { family: number; model: number; stepping: number } {
  const extendedFamily = (eax >>> 20) & 0xff;
  const extendedModel = (eax >>> 16) & 0xf;
  const familyID = (eax >>> 8) & 0xf;
  const modelID = (eax >>> 4) & 0xf;
  return {
    family: (extendedFamily + familyID) & 0xff,
    model: ((extendedModel << 4) | modelID) & 0xff,
    stepping: eax & 0xf,
  };
}

// productLineFromFms returns the KDS product line for a CPUID_1_EAX value
// (Go abi.SevProductFromCpuid1Eax + kds.ProductLineFromFms).
export function productLineFromFms(fms: number): string {
  const { family, model } = fmsFromCpuid1Eax(fms);
  switch (family) {
    case 0x19: // Zen 3 / Zen 4
      switch (model) {
        case 0x01:
          return "Milan";
        case 0x11:
          return "Genoa";
        default:
          return "Unknown";
      }
    case 0x1a: // Zen 5
      switch (model) {
        case 0x02:
          return "Turin";
        default:
          return "Unknown";
      }
    default:
      return "Unknown";
  }
}

// parseReport creates a SevReport from the little-endian ABI bytes,
// rejecting non-zero reserved regions (Go abi.ReportToProto).
export function parseReport(data: Uint8Array): SevReport {
  if (data.length < ReportSize) {
    throw new Error(
      `array size is 0x${data.length.toString(16)}, an SEV-SNP attestation report size is 0x${ReportSize.toString(16)}`,
    );
  }
  const version = u32(data, 0x00);
  const policy = u64(data, 0x08);
  try {
    parseSnpPolicy(policy);
  } catch (err) {
    throw new Error(`malformed guest policy: ${err instanceof Error ? err.message : String(err)}`);
  }
  const signatureAlgo = u32(data, 0x34);
  const signerInfoRaw = u32(data, 0x48);
  parseSignerInfo(signerInfoRaw);
  mbz(data, 0x4c, 0x50);

  let cpuid1EaxFms = 0;
  let mbzLo = 0x188;
  if (version >= ReportVersion3) {
    mbzLo = 0x18b;
    cpuid1EaxFms = fmsToCpuid1Eax(data[0x188], data[0x189], data[0x18a]);
  }
  mbz(data, mbzLo, 0x1a0);
  mbz(data, 0x1eb, 0x1ec);
  mbz(data, 0x1ef, 0x1f0);
  mbz(data, 0x208, signatureOffset);
  if (signatureAlgo === SignEcdsaP384Sha384) {
    mbz(data, signatureOffset + 2 * ecdsaRSSize, ReportSize);
  }

  return {
    raw: data,
    version,
    guestSvn: u32(data, 0x04),
    policy,
    familyId: data.slice(0x10, 0x20),
    imageId: data.slice(0x20, 0x30),
    vmpl: u32(data, 0x30),
    signatureAlgo,
    currentTcb: u64(data, 0x38),
    platformInfo: u64(data, 0x40),
    signerInfo: signerInfoRaw,
    reportData: data.slice(0x50, 0x90),
    measurement: data.slice(0x90, 0xc0),
    hostData: data.slice(0xc0, 0xe0),
    idKeyDigest: data.slice(0xe0, 0x110),
    authorKeyDigest: data.slice(0x110, 0x140),
    reportId: data.slice(0x140, 0x160),
    reportIdMa: data.slice(0x160, 0x180),
    reportedTcb: u64(data, 0x180),
    cpuid1EaxFms,
    chipId: data.slice(0x1a0, 0x1e0),
    committedTcb: u64(data, 0x1e0),
    currentBuild: data[0x1e8],
    currentMinor: data[0x1e9],
    currentMajor: data[0x1ea],
    committedBuild: data[0x1ec],
    committedMinor: data[0x1ed],
    committedMajor: data[0x1ee],
    launchTcb: u64(data, 0x1f0),
    launchMitVector: u64(data, 0x1f8),
    currentMitVector: u64(data, 0x200),
    signature: data.slice(signatureOffset, ReportSize),
  };
}

// validateReportFormat rejects structural violations (Go abi.ValidateReportFormat).
export function validateReportFormat(r: Uint8Array): void {
  if (r.length < ReportSize) {
    throw new Error(`report size is ${r.length} bytes. Expected ${ReportSize} bytes`);
  }
  const version = u32(r, 0x00);
  if (version < MinSupportedReportVersion || version > MaxSupportedReportVersion) {
    throw new Error(
      `report version is: ${version}. Expected between ${MinSupportedReportVersion} and ${MaxSupportedReportVersion}`,
    );
  }
  try {
    parseSnpPolicy(u64(r, 0x08));
  } catch (err) {
    throw new Error(`malformed guest policy: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// reportToSignatureRaw returns the report's ECDSA signature as big-endian
// raw r||s (96 bytes) for WebCrypto P-384 verification (Go
// abi.ReportToSignatureDER's throws, without the DER round trip). The ABI
// stores r and s as 72-byte little-endian values; a component whose upper 24
// bytes are non-zero is >= 2^384 and can never verify (the DER path encoded
// it and verification failed), so undefined is returned and the caller
// treats it as a signature verification failure.
export function reportToSignatureRaw(report: Uint8Array): Uint8Array | undefined {
  if (report.length !== ReportSize) {
    throw new Error(`incorrect report size: ${report.length.toString(16)}, want ${ReportSize.toString(16)}`);
  }
  const algo = u32(report, 0x34);
  if (algo !== SignEcdsaP384Sha384) {
    throw new Error(`unknown signature algorithm: ${algo}`);
  }
  const signature = report.subarray(signatureOffset, ReportSize);
  const out = new Uint8Array(96);
  for (let comp = 0; comp < 2; comp++) {
    const le = signature.subarray(comp * ecdsaRSSize, (comp + 1) * ecdsaRSSize);
    for (let i = 48; i < ecdsaRSSize; i++) {
      if (le[i] !== 0) return undefined;
    }
    for (let i = 0; i < 48; i++) out[comp * 48 + i] = le[47 - i];
  }
  return out;
}

// signedComponent returns the report bytes signed by the AMD-SP.
export function signedComponent(report: Uint8Array): Uint8Array {
  return report.subarray(0, signatureOffset);
}

// TCB struct versions: 0 for Milan & Genoa, 1 for Turin (Go kds).
export const TcbStructVersion0 = 0;
export const TcbStructVersion1 = 1;

// TCBParts represents all TCB field values of an AMD TCB_VERSION, tagged with
// the layout version they belong to (Go kds.TCBParts). fmcSpl is defined only
// for struct version 1 (Turin); spl4..spl7 only for struct version 0.
export interface TCBParts {
  version: number;
  blSpl: number;
  teeSpl: number;
  spl4: number;
  spl5: number;
  spl6: number;
  spl7: number;
  snpSpl: number;
  ucodeSpl: number;
  fmcSpl: number;
}

// productLineToTCBVersion returns the TCB struct version a product line uses in
// its V[CL]EK x509 extensions (Go kds.productLineToTCBVersion).
export function productLineToTCBVersion(productLine: string): number {
  if (productLine === "Milan" || productLine === "Genoa" || productLine === "Siena") {
    return TcbStructVersion0;
  }
  if (productLine === "Turin") {
    return TcbStructVersion1;
  }
  throw new Error(`invalid product line "${productLine}"`);
}

// newTCBParts validates and tags TCB component values with the layout used by
// productLine (Go kds.NewTCBParts).
export function newTCBParts(
  productLine: string,
  parts: { fmcSpl?: number; blSpl?: number; teeSpl?: number; snpSpl?: number; ucodeSpl?: number },
): TCBParts {
  const version = productLineToTCBVersion(productLine);
  const result: TCBParts = {
    version,
    fmcSpl: parts.fmcSpl ?? 0,
    blSpl: parts.blSpl ?? 0,
    teeSpl: parts.teeSpl ?? 0,
    spl4: 0,
    spl5: 0,
    spl6: 0,
    spl7: 0,
    snpSpl: parts.snpSpl ?? 0,
    ucodeSpl: parts.ucodeSpl ?? 0,
  };
  tcbPartsToVersion(result); // range/layout validation
  return result;
}

// tcbPartsToVersion composes (struct version, 64-bit TCB) from parts (Go
// kds.TCBParts.ToTCBVersionStruct). Only UcodeSpl may be 0-255; all others
// must be 0-127.
export function tcbPartsToVersion(parts: TCBParts): { structVersion: number; tcb: bigint } {
  const check127 = (name: string, value: number): void => {
    if (value > 127) throw new Error(`${name} TCB part is ${value}. Expect 0-127`);
  };
  check127("SnpSpl", parts.snpSpl);
  check127("Spl7", parts.spl7);
  check127("Spl6", parts.spl6);
  check127("Spl5", parts.spl5);
  check127("Spl4", parts.spl4);
  check127("TeeSpl", parts.teeSpl);
  check127("BlSpl", parts.blSpl);
  check127("FmcSpl", parts.fmcSpl);

  if (parts.version === TcbStructVersion0) {
    if (parts.fmcSpl !== 0) {
      throw new Error("FmcSpl is not defined for TCB struct version 0");
    }
    const tcb =
      (BigInt(parts.ucodeSpl) << 56n) |
      (BigInt(parts.snpSpl) << 48n) |
      (BigInt(parts.spl7) << 40n) |
      (BigInt(parts.spl6) << 32n) |
      (BigInt(parts.spl5) << 24n) |
      (BigInt(parts.spl4) << 16n) |
      (BigInt(parts.teeSpl) << 8n) |
      BigInt(parts.blSpl);
    return { structVersion: TcbStructVersion0, tcb };
  }
  if (parts.version === TcbStructVersion1) {
    if (parts.spl4 !== 0 || parts.spl5 !== 0 || parts.spl6 !== 0 || parts.spl7 !== 0) {
      throw new Error("reserved Turin TCB components must be zero");
    }
    const tcb =
      (BigInt(parts.ucodeSpl) << 56n) |
      (BigInt(parts.snpSpl) << 24n) |
      (BigInt(parts.teeSpl) << 16n) |
      (BigInt(parts.blSpl) << 8n) |
      BigInt(parts.fmcSpl);
    return { structVersion: TcbStructVersion1, tcb };
  }
  throw new Error(`unsupported TCB struct version: ${parts.version}`);
}

// decomposeTCB decodes the security patch levels from a 64-bit TCB under a
// layout version (Go kds.TCBVersionStruct.ToTCBParts).
export function decomposeTCB(version: number, tcb: bigint): TCBParts {
  const b = (shift: bigint): number => Number((tcb >> shift) & 0xffn);
  if (version === TcbStructVersion1) {
    // Turin reserves bits 55:32; rejecting non-zero values keeps them from
    // disappearing when the structured representation is composed again.
    const reserved = tcb & 0x00ffffff00000000n;
    if (reserved !== 0n) {
      throw new Error(`non-zero reserved bits in Turin TCB: 0x${reserved.toString(16)}`);
    }
    return {
      version,
      ucodeSpl: b(56n),
      snpSpl: b(24n),
      teeSpl: b(16n),
      blSpl: b(8n),
      fmcSpl: b(0n),
      spl4: 0,
      spl5: 0,
      spl6: 0,
      spl7: 0,
    };
  }
  if (version === TcbStructVersion0) {
    return {
      version,
      ucodeSpl: b(56n),
      snpSpl: b(48n),
      spl7: b(40n),
      spl6: b(32n),
      spl5: b(24n),
      spl4: b(16n),
      teeSpl: b(8n),
      blSpl: b(0n),
      fmcSpl: 0,
    };
  }
  throw new Error(`unknown TCB version: ${version}`);
}

// tcbPartsLE returns true iff both use the same layout and all components of
// tcb0 are <= tcb1's (Go kds.TCBPartsLE).
export function tcbPartsLE(tcb0: TCBParts, tcb1: TCBParts): boolean {
  return (
    tcb0.version === tcb1.version &&
    tcb0.ucodeSpl <= tcb1.ucodeSpl &&
    tcb0.snpSpl <= tcb1.snpSpl &&
    tcb0.spl7 <= tcb1.spl7 &&
    tcb0.spl6 <= tcb1.spl6 &&
    tcb0.spl5 <= tcb1.spl5 &&
    tcb0.spl4 <= tcb1.spl4 &&
    tcb0.teeSpl <= tcb1.teeSpl &&
    tcb0.blSpl <= tcb1.blSpl &&
    tcb0.fmcSpl <= tcb1.fmcSpl
  );
}
