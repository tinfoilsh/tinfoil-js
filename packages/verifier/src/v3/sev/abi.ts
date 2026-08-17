// AMD SEV-SNP ATTESTATION_REPORT ABI: the report layout, guest-policy /
// platform-info / signer-info bitfields, CPUID product identity, and TCB
// composition, ported 1:1 from github.com/google/go-sev-guest abi and kds.
// All errors are plain Errors; callers assign the rejection layer.

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
  tioEnabled: boolean;
}

// parseSnpPlatformInfo errors on unrecognized bits (Go abi.ParseSnpPlatformInfo).
export function parseSnpPlatformInfo(platformInfo: bigint): SnpPlatformInfo {
  if (bit(platformInfo, 6)) {
    throw new Error(`reserved platform info bit 6 set: 0x${platformInfo.toString(16)}`);
  }
  if (platformInfo & ~0xffn) {
    throw new Error(`unrecognized platform info bit(s): 0x${platformInfo.toString(16)}`);
  }
  return {
    smtEnabled: bit(platformInfo, 0),
    tsmeEnabled: bit(platformInfo, 1),
    eccEnabled: bit(platformInfo, 2),
    raplDisabled: bit(platformInfo, 3),
    ciphertextHidingDRAMEnabled: bit(platformInfo, 4),
    aliasCheckComplete: bit(platformInfo, 5),
    tioEnabled: bit(platformInfo, 7),
  };
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
        `mbz range [0x${lo.toString(16)}:0x${hi.toString(16)}] not all zero: ${Buffer.from(data.subarray(lo, hi)).toString("hex")}`,
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

// amdBigInt interprets an AMD little-endian byte string as an unsigned value.
function amdBigInt(le: Uint8Array): bigint {
  let v = 0n;
  for (let i = le.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(le[i]);
  return v;
}

function derIntegerFromBigInt(v: bigint): Uint8Array {
  let hex = v.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let bytes = Buffer.from(hex, "hex");
  if (bytes.length === 0) bytes = Buffer.from([0]);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return new Uint8Array(bytes);
}

function derLength(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  const b: number[] = [];
  while (n > 0) {
    b.unshift(n & 0xff);
    n >>= 8;
  }
  return new Uint8Array([0x80 | b.length, ...b]);
}

function derTLV(tag: number, content: Uint8Array): Uint8Array {
  const len = derLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

// reportToSignatureDER returns the report's signature component in DER
// format for ECDSA verification (Go abi.ReportToSignatureDER).
export function reportToSignatureDER(report: Uint8Array): Uint8Array {
  if (report.length !== ReportSize) {
    throw new Error(`incorrect report size: ${report.length.toString(16)}, want ${ReportSize.toString(16)}`);
  }
  const algo = u32(report, 0x34);
  if (algo !== SignEcdsaP384Sha384) {
    throw new Error(`unknown signature algorithm: ${algo}`);
  }
  const signature = report.subarray(signatureOffset, ReportSize);
  const r = derTLV(0x02, derIntegerFromBigInt(amdBigInt(signature.subarray(0x00, 0x48))));
  const s = derTLV(0x02, derIntegerFromBigInt(amdBigInt(signature.subarray(0x48, 0x90))));
  const seq = new Uint8Array(r.length + s.length);
  seq.set(r, 0);
  seq.set(s, r.length);
  return derTLV(0x30, seq);
}

// signedComponent returns the report bytes signed by the AMD-SP.
export function signedComponent(report: Uint8Array): Uint8Array {
  return report.subarray(0, signatureOffset);
}

// TCBParts represents all TCB field values of an AMD TCB_VERSION (Go kds.TCBParts).
export interface TCBParts {
  blSpl: number;
  teeSpl: number;
  spl4: number;
  spl5: number;
  spl6: number;
  spl7: number;
  snpSpl: number;
  ucodeSpl: number;
}

// composeTCBParts returns a TCB_VERSION from part values (Go kds.ComposeTCBParts).
export function composeTCBParts(parts: TCBParts): bigint {
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
  return (
    (BigInt(parts.ucodeSpl) << 56n) |
    (BigInt(parts.snpSpl) << 48n) |
    (BigInt(parts.spl7) << 40n) |
    (BigInt(parts.spl6) << 32n) |
    (BigInt(parts.spl5) << 24n) |
    (BigInt(parts.spl4) << 16n) |
    (BigInt(parts.teeSpl) << 8n) |
    BigInt(parts.blSpl)
  );
}

// decomposeTCBVersion interprets the TCB_VERSION bytes (Go kds.DecomposeTCBVersion).
export function decomposeTCBVersion(tcb: bigint): TCBParts {
  const b = (shift: bigint): number => Number((tcb >> shift) & 0xffn);
  return {
    ucodeSpl: b(56n),
    snpSpl: b(48n),
    spl7: b(40n),
    spl6: b(32n),
    spl5: b(24n),
    spl4: b(16n),
    teeSpl: b(8n),
    blSpl: b(0n),
  };
}

// tcbPartsLE returns true iff all components of tcb0 are <= tcb1's (Go kds.TCBPartsLE).
export function tcbPartsLE(tcb0: TCBParts, tcb1: TCBParts): boolean {
  return (
    tcb0.ucodeSpl <= tcb1.ucodeSpl &&
    tcb0.snpSpl <= tcb1.snpSpl &&
    tcb0.spl7 <= tcb1.spl7 &&
    tcb0.spl6 <= tcb1.spl6 &&
    tcb0.spl5 <= tcb1.spl5 &&
    tcb0.spl4 <= tcb1.spl4 &&
    tcb0.teeSpl <= tcb1.teeSpl &&
    tcb0.blSpl <= tcb1.blSpl
  );
}
