/**
 * The SEV-SNP attestation report: a fixed 1184-byte little-endian structure.
 * Every reserved range must be zero, the guest policy and signer fields must
 * be well formed, and the product line is read from the CPUID family and
 * model the firmware records from report version 3 on.
 */
import type { Register } from "../../../measurement.js";

export const REPORT_SIZE = 1184;
export const PRODUCT_GENOA = "Genoa";
export const PRODUCT_TURIN = "Turin";
export type ProductLine = typeof PRODUCT_GENOA | typeof PRODUCT_TURIN;

/** SIGNATURE_ALGO value for ECDSA P-384 with SHA-384, the only one accepted. */
export const SIGNATURE_ALGO_ECDSA_P384_SHA384 = 1;

export const CHIP_ID_SIZE = 64;
export const REPORT_DATA_SIZE = 64;
export const HOST_DATA_SIZE = 32;
export const FAMILY_ID_SIZE = 16;
export const IMAGE_ID_SIZE = 16;

const SIGNATURE_OFFSET = 0x2a0;
/** Each of r and s occupies 72 little-endian bytes. */
const ECDSA_RS_SIZE = 72;
const REPORT_VERSION_3 = 3;
/** The first report version that carries LAUNCH_MIT_VECTOR and CURRENT_MIT_VECTOR; earlier versions reserve those bytes. */
const REPORT_VERSION_5 = 5;
const MIT_VECTORS_OFFSET = 0x1f8;
const MIT_VECTORS_END = 0x208;

/** Which key signed the report (SIGNER_INFO bits 4:2). */
export const SIGNER_VCEK = 0;
export const SIGNER_VLEK = 1;
export const SIGNER_NONE = 7;

export interface SignerInfo {
  /** SIGNER_VCEK, SIGNER_VLEK or SIGNER_NONE; the reserved values reject at parse. */
  readonly signingKey: number;
  readonly maskChipKey: boolean;
  readonly authorKeyEn: boolean;
}

/** The guest policy bits a report states; ABI major/minor is a version floor, the rest are flags. */
export interface GuestPolicyBits {
  readonly abiMajor: number;
  readonly abiMinor: number;
  readonly smt: boolean;
  readonly migrateMa: boolean;
  readonly debug: boolean;
  readonly singleSocket: boolean;
  readonly cxlAllowed: boolean;
  readonly memAes256Xts: boolean;
  readonly raplDis: boolean;
  readonly ciphertextHidingDram: boolean;
  readonly pageSwapDisable: boolean;
}

/** The PLATFORM_INFO flags; bits above 7 are reserved and reject. */
export interface PlatformInfoBits {
  readonly smtEnabled: boolean;
  readonly tsmeEnabled: boolean;
  readonly eccEnabled: boolean;
  readonly raplDisabled: boolean;
  readonly ciphertextHidingDram: boolean;
  readonly aliasCheckComplete: boolean;
  readonly iommuWriteSafe: boolean;
  readonly tioEnabled: boolean;
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
  readonly signer: SignerInfo;
  readonly reportData: Uint8Array;
  readonly measurement: Register;
  readonly hostData: Uint8Array;
  readonly idKeyDigest: Uint8Array;
  readonly authorKeyDigest: Uint8Array;
  readonly reportId: Uint8Array;
  readonly reportIdMa: Uint8Array;
  readonly reportedTcb: bigint;
  /** CPUID(1).EAX family/model/stepping recomposed; 0 when the report predates version 3. */
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
  /** Zero in reports before version 5, which reserve the field. */
  readonly launchMitVector: bigint;
  readonly currentMitVector: bigint;
  /** r‖s, each 72 little-endian bytes. */
  readonly signature: Uint8Array;
}

const POLICY_RESERVED_1_BIT = 17n;
const POLICY_SMT_BIT = 16n;
const POLICY_MIGRATE_MA_BIT = 18n;
const POLICY_DEBUG_BIT = 19n;
const POLICY_SINGLE_SOCKET_BIT = 20n;
const POLICY_CXL_ALLOW_BIT = 21n;
const POLICY_MEM_AES256_XTS_BIT = 22n;
const POLICY_RAPL_DIS_BIT = 23n;
const POLICY_CIPHERTEXT_HIDING_DRAM_BIT = 24n;
const POLICY_PAGE_SWAP_DISABLE_BIT = 25n;

const bit = (v: bigint, n: bigint): boolean => ((v >> n) & 1n) === 1n;

/** Decodes the guest policy: bit 17 must be set and bits 63:26 clear. */
export function parseGuestPolicy(policy: bigint): GuestPolicyBits {
  if (!bit(policy, POLICY_RESERVED_1_BIT)) throw new Error(`guest policy bit ${POLICY_RESERVED_1_BIT} is reserved and must be 1`);
  if (policy >> 26n !== 0n) throw new Error("guest policy bits 63:26 are reserved and must be zero");
  return {
    abiMinor: Number(policy & 0xffn),
    abiMajor: Number((policy >> 8n) & 0xffn),
    smt: bit(policy, POLICY_SMT_BIT),
    migrateMa: bit(policy, POLICY_MIGRATE_MA_BIT),
    debug: bit(policy, POLICY_DEBUG_BIT),
    singleSocket: bit(policy, POLICY_SINGLE_SOCKET_BIT),
    cxlAllowed: bit(policy, POLICY_CXL_ALLOW_BIT),
    memAes256Xts: bit(policy, POLICY_MEM_AES256_XTS_BIT),
    raplDis: bit(policy, POLICY_RAPL_DIS_BIT),
    ciphertextHidingDram: bit(policy, POLICY_CIPHERTEXT_HIDING_DRAM_BIT),
    pageSwapDisable: bit(policy, POLICY_PAGE_SWAP_DISABLE_BIT),
  };
}

/** Decodes PLATFORM_INFO; any bit above 7 rejects. */
export function parsePlatformInfo(info: bigint): PlatformInfoBits {
  if (info >> 8n !== 0n) throw new Error(`unrecognized platform info bit(s): 0x${info.toString(16)}`);
  return {
    smtEnabled: bit(info, 0n),
    tsmeEnabled: bit(info, 1n),
    eccEnabled: bit(info, 2n),
    raplDisabled: bit(info, 3n),
    ciphertextHidingDram: bit(info, 4n),
    aliasCheckComplete: bit(info, 5n),
    iommuWriteSafe: bit(info, 6n),
    tioEnabled: bit(info, 7n),
  };
}

/** Decodes SIGNER_INFO: bits 31:5 must be zero and the signing key must not be a reserved value. */
export function parseSignerInfo(info: number): SignerInfo {
  if (info >>> 5 !== 0) throw new Error("SIGNER_INFO bits 31:5 are reserved and must be zero");
  const signingKey = (info >>> 2) & 7;
  if (signingKey > SIGNER_VLEK && signingKey < SIGNER_NONE) {
    throw new Error(`SIGNER_INFO signing key values 2-6 are reserved, got ${signingKey}`);
  }
  return { signingKey, maskChipKey: (info & 2) !== 0, authorKeyEn: (info & 1) !== 0 };
}

function mustBeZero(bytes: Uint8Array, lo: number, hi: number): void {
  for (let i = lo; i < hi; i++) {
    if (bytes[i] !== 0) throw new Error(`report bytes 0x${lo.toString(16)}:0x${hi.toString(16)} are reserved and must be zero`);
  }
}

/** CPUID(1).EAX from a family, model and stepping, as the report stores them. */
export function cpuid1EaxOf(family: number, model: number, stepping: number): number {
  let extendedFamily = 0;
  let familyId = family;
  if (family >= 0xf) {
    extendedFamily = family - 0xf;
    familyId = 0xf;
  }
  const extendedModel = model >> 4;
  const modelId = model & 0xf;
  return ((extendedFamily << 20) | (extendedModel << 16) | (familyId << 8) | (modelId << 4) | (stepping & 0xf)) >>> 0;
}

/** The family, model and stepping of a CPUID(1).EAX value. */
export function fmsOf(eax: number): { family: number; model: number; stepping: number } {
  const extendedFamily = (eax >>> 20) & 0xff;
  const extendedModel = (eax >>> 16) & 0xf;
  const familyId = (eax >>> 8) & 0xf;
  const modelId = (eax >>> 4) & 0xf;
  return { family: (extendedFamily + familyId) & 0xff, model: ((extendedModel << 4) | modelId) & 0xff, stepping: eax & 0xf };
}

/** Decodes the 1184-byte report; a wrong length or a non-zero reserved range rejects. */
export function parseReport(bytes: Uint8Array): SevReport {
  if (bytes.length !== REPORT_SIZE) throw new Error(`SEV-SNP report must be exactly ${REPORT_SIZE} bytes, got ${bytes.length}`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u32 = (at: number): number => view.getUint32(at, true);
  const u64 = (at: number): bigint => view.getBigUint64(at, true);
  const slice = (at: number, len: number): Uint8Array => bytes.slice(at, at + len);

  const version = u32(0x00);
  const policy = u64(0x08);
  parseGuestPolicy(policy);
  const signerInfo = u32(0x48);
  const signer = parseSignerInfo(signerInfo);
  mustBeZero(bytes, 0x4c, 0x50);

  let cpuid1Eax = 0;
  let reservedFrom = 0x188;
  if (version >= REPORT_VERSION_3) {
    reservedFrom = 0x18b;
    cpuid1Eax = cpuid1EaxOf(bytes[0x188], bytes[0x189], bytes[0x18a]);
  }
  mustBeZero(bytes, reservedFrom, 0x1a0);
  mustBeZero(bytes, 0x1eb, 0x1ec);
  mustBeZero(bytes, 0x1ef, 0x1f0);
  // The mitigation vectors exist from version 5; earlier versions reserve
  // their bytes, so a value there is not evidence and rejects.
  const hasMitVectors = version >= REPORT_VERSION_5;
  if (!hasMitVectors) mustBeZero(bytes, MIT_VECTORS_OFFSET, MIT_VECTORS_END);
  mustBeZero(bytes, MIT_VECTORS_END, SIGNATURE_OFFSET);
  const signatureAlgo = u32(0x34);
  if (signatureAlgo === SIGNATURE_ALGO_ECDSA_P384_SHA384) {
    mustBeZero(bytes, SIGNATURE_OFFSET + 2 * ECDSA_RS_SIZE, REPORT_SIZE);
  }

  return {
    version,
    guestSvn: u32(0x04),
    policy,
    familyId: slice(0x10, FAMILY_ID_SIZE),
    imageId: slice(0x20, IMAGE_ID_SIZE),
    vmpl: u32(0x30),
    signatureAlgo,
    currentTcb: u64(0x38),
    platformInfo: u64(0x40),
    signerInfo,
    signer,
    reportData: slice(0x50, REPORT_DATA_SIZE),
    measurement: slice(0x90, 48),
    hostData: slice(0xc0, HOST_DATA_SIZE),
    idKeyDigest: slice(0xe0, 48),
    authorKeyDigest: slice(0x110, 48),
    reportId: slice(0x140, 32),
    reportIdMa: slice(0x160, 32),
    reportedTcb: u64(0x180),
    cpuid1Eax,
    chipId: slice(0x1a0, CHIP_ID_SIZE),
    committedTcb: u64(0x1e0),
    currentBuild: bytes[0x1e8],
    currentMinor: bytes[0x1e9],
    currentMajor: bytes[0x1ea],
    committedBuild: bytes[0x1ec],
    committedMinor: bytes[0x1ed],
    committedMajor: bytes[0x1ee],
    launchTcb: u64(0x1f0),
    launchMitVector: hasMitVectors ? u64(MIT_VECTORS_OFFSET) : 0n,
    currentMitVector: hasMitVectors ? u64(MIT_VECTORS_OFFSET + 8) : 0n,
    signature: slice(SIGNATURE_OFFSET, 2 * ECDSA_RS_SIZE),
  };
}

/** The bytes the report signature covers: everything before SIGNATURE. */
export function signedBytes(bytes: Uint8Array): Uint8Array {
  return bytes.subarray(0, SIGNATURE_OFFSET);
}

/**
 * The report signature as fixed-width big-endian r‖s (48 bytes each). Each
 * component is stored little-endian in 72 bytes; the high 24 bytes must be
 * zero for a P-384 scalar, so a value that uses them cannot be a valid
 * signature and rejects.
 */
export function signatureRaw(report: SevReport): Uint8Array {
  const out = new Uint8Array(96);
  for (let part = 0; part < 2; part++) {
    const le = report.signature.subarray(part * ECDSA_RS_SIZE, (part + 1) * ECDSA_RS_SIZE);
    for (let i = 48; i < ECDSA_RS_SIZE; i++) {
      if (le[i] !== 0) throw new Error("report signature component exceeds the P-384 scalar size");
    }
    for (let i = 0; i < 48; i++) out[part * 48 + i] = le[47 - i];
  }
  return out;
}

/**
 * The product line from the report's CPUID family and model: Genoa (family
 * 0x19, model 0x11) or Turin (family 0x1a, model 0x02). A report without
 * CPUID identity (version 2) or of another product rejects.
 */
export function productLine(report: SevReport): ProductLine {
  if (report.cpuid1Eax === 0) {
    throw new Error(`report carries no CPUID product identity (report version ${report.version}, want 3+)`);
  }
  const { family, model } = fmsOf(report.cpuid1Eax);
  if (family === 0x19 && model === 0x11) return PRODUCT_GENOA;
  if (family === 0x1a && model === 0x02) return PRODUCT_TURIN;
  throw new Error(`unsupported SEV product in report CPUID 0x${report.cpuid1Eax.toString(16)}`);
}

export function allZero(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b !== 0) return false;
  return true;
}
