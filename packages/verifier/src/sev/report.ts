import type { SignerInfo, TCBParts, SnpPlatformInfo, SnpPolicy } from './types.js';
import {
  POLICY_RESERVED_1_BIT,
  REPORT_SIZE,
  SIGNATURE_OFFSET,
  ECDSA_P384_SHA384_SIGNATURE_SIZE,
  ZEN3ZEN4_FAMILY,
  ZEN5_FAMILY,
  MILAN_MODEL,
  GENOA_MODEL,
  TURIN_MODEL,
  ReportSigner
} from './constants.js';
import { policyFromInt, platformInfoFromInt } from './utils.js';
import { AttestationError } from '../errors.js';

/**
 * SEV-SNP attestation report
 */
export class Report {
  version: number;  // Should be 2 for revision 1.55, 3 for revision 1.56, 5 for revision 1.58
  guestSvn: number;
  policy: bigint;
  policyParsed: SnpPolicy;
  familyId: Uint8Array;  // Should be 16 bytes long
  imageId: Uint8Array;   // Should be 16 bytes long
  vmpl: number;
  signatureAlgo: number;
  currentTcb: bigint;
  platformInfo: bigint;
  platformInfoParsed: SnpPlatformInfo;
  signerInfo: number;  // AuthorKeyEn, MaskChipKey, SigningKey
  signerInfoParsed: SignerInfo;
  reportData: Uint8Array;  // Should be 64 bytes long
  measurement: Uint8Array;  // Should be 48 bytes long
  hostData: Uint8Array;   // Should be 32 bytes long
  idKeyDigest: Uint8Array;  // Should be 48 bytes long
  authorKeyDigest: Uint8Array;  // Should be 48 bytes long
  reportId: Uint8Array;   // Should be 32 bytes long
  reportIdMa: Uint8Array;  // Should be 32 bytes long
  reportedTcb: bigint;
  chipId: Uint8Array;  // Should be 64 bytes long
  committedTcb: bigint;
  currentBuild: number;
  currentMinor: number;
  currentMajor: number;
  committedBuild: number;
  committedMinor: number;
  committedMajor: number;
  launchTcb: bigint;
  signedData: Uint8Array;
  signature: Uint8Array;  // Should be 512 bytes long
  family: number;
  model: number;
  stepping: number;
  productName: string;

  /**
   * Parse an attestation report from raw bytes in SEV SNP ABI format.
   *
   * @param data - Raw bytes of the attestation report
   * @returns Report object containing parsed data
   * @throws Error if data is malformed or validation fails
   */
  constructor(data: Uint8Array) {
    if (data.length < REPORT_SIZE) {
      throw new AttestationError(`Array size is 0x${data.length.toString(16)}, an SEV-SNP attestation report size is 0x${REPORT_SIZE.toString(16)}`);
    }

    // Parse all fields using little-endian byte order
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

    this.version = view.getUint32(0x00, true);
    this.guestSvn = view.getUint32(0x04, true);
    this.policy = view.getBigUint64(0x08, true);

    // Check reserved bit must be 1
    if (!(this.policy & (1n << BigInt(POLICY_RESERVED_1_BIT)))) {
      throw new AttestationError(`policy[${POLICY_RESERVED_1_BIT}] is reserved, must be 1, got 0`);
    }

    // Check bits 63-26 must be zero
    if (this.policy >> 26n) {
      throw new AttestationError('policy bits 63-26 must be zero');
    }

    this.familyId = data.slice(0x10, 0x20);  // 16 bytes
    this.imageId = data.slice(0x20, 0x30);   // 16 bytes
    this.vmpl = view.getUint32(0x30, true);
    this.signatureAlgo = view.getUint32(0x34, true);
    this.currentTcb = view.getBigUint64(0x38, true);

    try {
      mbz64(this.currentTcb, 'current_tcb', 47, 16);
    } catch (e) {
      throw new AttestationError('current_tcb not correctly formed', { cause: e as Error });
    }

    this.platformInfo = view.getBigUint64(0x40, true);
    // Decode additional helper structures for easier consumption later.
    this.policyParsed = policyFromInt(this.policy);
    this.platformInfoParsed = platformInfoFromInt(this.platformInfo);
    this.signerInfo = view.getUint32(0x48, true);

    try {
      mbz64(BigInt(this.signerInfo), 'signer_info', 31, 5);
    } catch (e) {
      throw new AttestationError('signer_info not correctly formed', { cause: e as Error });
    }

    const signingKey = (this.signerInfo >> 2) & 7;
    if (signingKey !== ReportSigner.VcekReportSigner) {
      throw new AttestationError(`This implementation only supports VCEK signed reports. Got ${signingKey}`);
    }

    this.signerInfoParsed = {
      signingKey: signingKey,
      maskChipKey: !!(this.signerInfo & 2),
      authorKeyEn: !!(this.signerInfo & 1),
    };

    try {
      mbz(data, 0x4c, 0x50);
    } catch (e) {
      throw new AttestationError('report_data not correctly formed', { cause: e as Error });
    }

    // 0x4C-0x50 is MBZ (Must Be Zero)
    this.reportData = data.slice(0x50, 0x90);      // 64 bytes
    this.measurement = data.slice(0x90, 0xc0);      // 48 bytes
    this.hostData = data.slice(0xc0, 0xe0);        // 32 bytes
    this.idKeyDigest = data.slice(0xe0, 0x110);    // 48 bytes
    this.authorKeyDigest = data.slice(0x110, 0x140);  // 48 bytes
    this.reportId = data.slice(0x140, 0x160);       // 32 bytes
    this.reportIdMa = data.slice(0x160, 0x180);    // 32 bytes
    this.reportedTcb = view.getBigUint64(0x180, true);

    try {
      mbz64(this.reportedTcb, 'reported_tcb', 47, 16);
    } catch (e) {
      throw new AttestationError('reported_tcb not correctly formed', { cause: e as Error });
    }

    let mbzLo = 0x188;
    // Version specific parsing
    if (this.version >= 3) {  // Report Version 3
      this.family = view.getUint8(0x188);
      this.model = view.getUint8(0x189);
      this.stepping = view.getUint8(0x18a);
      this.productName = this.initProductName();
      mbzLo = 0x18b;
    } else if (this.version === 2) {  // Report Version 2
      this.family = ZEN3ZEN4_FAMILY;
      this.model = GENOA_MODEL;
      this.stepping = 0x01;
      this.productName = 'Genoa';
    } else {
      throw new AttestationError('Unknown report version');
    }

    try {
      mbz(data, mbzLo, 0x1a0);
    } catch (e) {
      throw new AttestationError('report_data not correctly formed', { cause: e as Error });
    }

    this.chipId = data.slice(0x1a0, 0x1e0);        // 64 bytes
    this.committedTcb = view.getBigUint64(0x1e0, true);

    try {
      mbz64(this.committedTcb, 'committed_tcb', 47, 16);
    } catch (e) {
      throw new AttestationError('committed_tcb not correctly formed', { cause: e as Error });
    }

    // Version fields
    this.currentBuild = view.getUint8(0x1e8);
    this.currentMinor = view.getUint8(0x1e9);
    this.currentMajor = view.getUint8(0x1ea);

    try {
      mbz(data, 0x1eb, 0x1ec);
    } catch (e) {
      throw new AttestationError('report_data not correctly formed', { cause: e as Error });
    }

    this.committedBuild = view.getUint8(0x1ec);
    this.committedMinor = view.getUint8(0x1ed);
    this.committedMajor = view.getUint8(0x1ee);

    try {
      mbz(data, 0x1ef, 0x1f0);
    } catch (e) {
      throw new AttestationError('report_data not correctly formed', { cause: e as Error });
    }

    this.launchTcb = view.getBigUint64(0x1f0, true);

    try {
      mbz64(this.launchTcb, 'launch_tcb', 47, 16);
    } catch (e) {
      throw new AttestationError('launch_tcb not correctly formed', { cause: e as Error });
    }

    try {
      mbz(data, 0x1f8, SIGNATURE_OFFSET);
    } catch (e) {
      throw new AttestationError('report_data not correctly formed', { cause: e as Error });
    }

    if (this.signatureAlgo === 1) {  // ECDSA P-384 SHA-384
      try {
        mbz(data, SIGNATURE_OFFSET + ECDSA_P384_SHA384_SIGNATURE_SIZE, REPORT_SIZE);
      } catch (e) {
        throw new AttestationError('report_data not correctly formed', { cause: e as Error });
      }
    }

    this.signedData = data.slice(0, SIGNATURE_OFFSET);
    this.signature = data.slice(SIGNATURE_OFFSET, REPORT_SIZE);
  }

  private initProductName(): string {
    if (this.family === ZEN3ZEN4_FAMILY) {
      if (this.model === MILAN_MODEL) return 'Milan';
      if (this.model === GENOA_MODEL) return 'Genoa';
    } else if (this.family === ZEN5_FAMILY) {
      if (this.model === TURIN_MODEL) return 'Turin';
    }
    return 'Unknown';
  }
}

/**
 * Returns the first index which is not zero, otherwise returns hi.
 *
 * @param data - Bytes to search through
 * @param lo - Starting index (inclusive)
 * @param hi - Ending index (exclusive)
 * @returns Index of first non-zero byte, or hi if all bytes are zero
 */
function findNonZero(data: Uint8Array, lo: number, hi: number): number {
  for (let i = lo; i < hi; i++) {
    if (data[i] !== 0) return i;
  }
  return hi;
}

/**
 * Checks if a range of bytes is all zeros.
 *
 * @param data - Bytes to check
 * @param lo - Starting index (inclusive)
 * @param hi - Ending index (exclusive)
 * @throws Error if any byte in the range is non-zero
 */
function mbz(data: Uint8Array, lo: number, hi: number): void {
  const firstNonZero = findNonZero(data, lo, hi);
  if (firstNonZero !== hi) {
    const hexStr = Array.from(data.slice(lo, hi))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    throw new AttestationError(`mbz range [0x${lo.toString(16)}:0x${hi.toString(16)}] not all zero: ${hexStr}`);
  }
}

/**
 * Checks if a range of bits in an integer is all zeros.
 *
 * @param data - Integer to check
 * @param base - String identifier for error message
 * @param hi - Highest bit position (inclusive)
 * @param lo - Lowest bit position (inclusive)
 * @throws Error if any bit in the range is non-zero
 */
function mbz64(data: bigint, base: string, hi: number, lo: number): void {
  // Create mask for the bit range
  const mask = (1n << BigInt(hi - lo + 1)) - 1n;
  // Extract and check the bits
  const bits = (data >> BigInt(lo)) & mask;
  if (bits !== 0n) {
    throw new AttestationError(`mbz range ${base}[0x${lo.toString(16)}:0x${hi.toString(16)}] not all zero: ${data.toString(16)}`);
  }
}
