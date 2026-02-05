import { Report } from './report.js';
import { CertificateChain } from './cert-chain.js';
import type { TCBParts, SnpPolicy, SnpPlatformInfo } from './types.js';
import { tcbFromInt, tcbMeetsMinimum, bytesToHex } from './utils.js';
import { ReportSigner } from './constants.js';
import { uint8ArrayEqual } from '@freedomofpress/crypto-browser';
import { ValidationError } from '../errors.js';

/**
 * Verification options for an SEV-SNP attestation report.
 * Any attribute left as undefined will not be checked by the validation routine.
 */
export interface ValidationOptions {
  // Policy / version constraints
  guestPolicy?: SnpPolicy;
  minimumGuestSvn?: number;
  minimumBuild?: number;          // Firmware build (uint8)
  minimumVersion?: number;        // Firmware API version (uint16)

  // TCB requirements
  minimumTcb?: TCBParts;
  minimumLaunchTcb?: TCBParts;
  permitProvisionalFirmware: boolean;

  // Field equality checks (length is not enforced here; caller must ensure correctness)
  reportData?: Uint8Array;          // 64 bytes
  hostData?: Uint8Array;            // 32 bytes
  imageId?: Uint8Array;             // 16 bytes
  familyId?: Uint8Array;            // 16 bytes
  reportId?: Uint8Array;            // 32 bytes
  reportIdMa?: Uint8Array;          // 32 bytes
  measurement?: Uint8Array;         // 48 bytes
  chipId?: Uint8Array;              // 64 bytes

  // Misc
  platformInfo?: SnpPlatformInfo;
  vmpl?: number;                    // Expected VMPL (0-3)

  // TODO: ID-block / author key requirements
  requireAuthorKey: boolean;
  requireIdBlock: boolean;
  // trustedAuthorKeys: x509.Certificate[]
  // trustedAuthorKeyHashes: Uint8Array[]
  // trustedIdKeys: x509.Certificate[]
  // trustedIdKeyHashes: Uint8Array[]

  // TODO: Extended certificate-table options
  // certTableOptions: Map<string, CertEntryOption>
}

// Default validation options 
export const defaultValidationOptions: ValidationOptions = {
  guestPolicy: {
    abiMinor: 0,
    abiMajor: 0,
    smt: true,
    migrateMa: false,
    debug: false,
    singleSocket: false,
    cxlAllowed: false,
    memAes256Xts: false,
    raplDis: false,
    ciphertextHidingDram: false,
    pageSwapDisabled: false,
  },
  minimumGuestSvn: 0,
  minimumBuild: 21,
  minimumVersion: (1 << 8) | 55,  // 1.55
  minimumTcb: {
    blSpl: 0x7,
    teeSpl: 0,
    snpSpl: 0xe,
    ucodeSpl: 0x48,
  },
  minimumLaunchTcb: {
    blSpl: 0x7,
    teeSpl: 0,
    snpSpl: 0xe,
    ucodeSpl: 0x48,
  },
  permitProvisionalFirmware: false,
  platformInfo: {
    smtEnabled: true,
    tsmeEnabled: true,
    eccEnabled: false,
    raplDisabled: false,
    ciphertextHidingDramEnabled: false,
    aliasCheckComplete: false,
    tioEnabled: false,
  },
  requireAuthorKey: false,
  requireIdBlock: false,
};

/**
 * Validate policy with security-aware checks.
 *
 * Logic:
 * - Check ABI version compatibility
 * - Reject unauthorized capabilities (report has them, required doesn't allow)
 * - Reject missing required restrictions/features
 *
 * @param reportPolicy - The policy from the attestation report
 * @param required - The required policy constraints
 * @throws Error if validation fails
 */
function validatePolicy(reportPolicy: SnpPolicy, required: SnpPolicy) {
  // ABI version check - required version must not be greater than report version
  if (comparePolicyVersions(required, reportPolicy) > 0) {
    throw new ValidationError(`Required ABI version (${required.abiMajor}.${required.abiMinor}) is greater than report's ABI version (${reportPolicy.abiMajor}.${reportPolicy.abiMinor})`);
  }

  // Unauthorized capabilities (report has them enabled, but required doesn't allow)
  if (!required.migrateMa && reportPolicy.migrateMa) {
    throw new ValidationError(`Found unauthorized migration agent capability. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (!required.debug && reportPolicy.debug) {
    throw new ValidationError(`Found unauthorized debug capability. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (!required.smt && reportPolicy.smt) {
    throw new ValidationError(`Found unauthorized symmetric multithreading (SMT) capability. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (!required.cxlAllowed && reportPolicy.cxlAllowed) {
    throw new ValidationError(`Found unauthorized CXL capability. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (!required.memAes256Xts && reportPolicy.memAes256Xts) {
    throw new ValidationError(`Found unauthorized memory encryption mode. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  // Required restrictions/features (report lacks what required mandates)
  if (required.singleSocket && !reportPolicy.singleSocket) {
    throw new ValidationError(`Required single socket restriction not present. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (required.memAes256Xts && !reportPolicy.memAes256Xts) {
    throw new ValidationError(`Found unauthorized memory encryption mode. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (required.raplDis && !reportPolicy.raplDis) {
    throw new ValidationError(`Found unauthorized RAPL capability. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (required.ciphertextHidingDram && !reportPolicy.ciphertextHidingDram) {
    throw new ValidationError(`Ciphertext hiding in DRAM isn't enforced. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }

  if (required.pageSwapDisabled && !reportPolicy.pageSwapDisabled) {
    throw new ValidationError(`Page swap isn't disabled. Report policy: ${JSON.stringify(reportPolicy)}, Required policy: ${JSON.stringify(required)}`);
  }
}

/**
 * Compare policy ABI versions.
 *
 * @param required - Required policy
 * @param report - Report policy
 * @returns > 0 if required version is greater than report version,
 *          = 0 if versions are equal,
 *          < 0 if required version is less than report version
 */
function comparePolicyVersions(required: SnpPolicy, report: SnpPolicy): number {
  // Compare major version first
  if (required.abiMajor !== report.abiMajor) {
    return required.abiMajor - report.abiMajor;
  }

  // If major versions are equal, compare minor versions
  return required.abiMinor - report.abiMinor;
}

function tcbPartsToString(tcb: TCBParts): string {
  return `TCBParts(bootloader=${tcb.blSpl}, tee=${tcb.teeSpl}, snp=${tcb.snpSpl}, microcode=${tcb.ucodeSpl})`;
}

/**
 * Validate the supplied SEV-SNP attestation report according to options.
 *
 * @param report - The attestation report to validate
 * @param chain - The certificate chain
 * @param options - Validation options
 * @throws Error if validation fails
 */
export function validateReport(report: Report, chain: CertificateChain, options: ValidationOptions): void {
  // Policy constraints
  if (options.guestPolicy) {
    validatePolicy(report.policyParsed, options.guestPolicy);
  }

  if (options.minimumGuestSvn !== undefined) {
    if (report.guestSvn < options.minimumGuestSvn) {
      throw new ValidationError(`Guest SVN ${report.guestSvn} is less than minimum required ${options.minimumGuestSvn}`);
    }
  }

  if (options.minimumBuild !== undefined) {
    if (report.currentBuild < options.minimumBuild) {
      throw new ValidationError(`Current SNP firmware build number ${report.currentBuild} is less than minimum required ${options.minimumBuild}`);
    }
    if (report.committedBuild < options.minimumBuild) {
      throw new ValidationError(`Committed SNP firmware build number ${report.committedBuild} is less than minimum required ${options.minimumBuild}`);
    }
  }

  if (options.minimumVersion !== undefined) {
    const currentVersion = (report.currentMajor << 8) | report.currentMinor;
    const committedVersion = (report.committedMajor << 8) | report.committedMinor;
    if (currentVersion < options.minimumVersion) {
      throw new ValidationError(`Current SNP firmware version ${report.currentMajor}.${report.currentMinor} is less than minimum required ${options.minimumVersion >> 8}.${options.minimumVersion & 0xff}`);
    }
    if (committedVersion < options.minimumVersion) {
      throw new ValidationError(`Committed SNP firmware version ${report.committedMajor}.${report.committedMinor} is less than minimum required ${options.minimumVersion >> 8}.${options.minimumVersion & 0xff}`);
    }
  }

  // TCB requirements
  if (options.minimumTcb) {
    const currentTcbParts = tcbFromInt(report.currentTcb);
    const committedTcbParts = tcbFromInt(report.committedTcb);
    const reportedTcbParts = tcbFromInt(report.reportedTcb);

    if (!tcbMeetsMinimum(currentTcbParts, options.minimumTcb)) {
      throw new ValidationError(`Current TCB ${tcbPartsToString(currentTcbParts)} does not meet minimum requirements ${tcbPartsToString(options.minimumTcb)}`);
    }
    if (!tcbMeetsMinimum(committedTcbParts, options.minimumTcb)) {
      throw new ValidationError(`Committed TCB ${tcbPartsToString(committedTcbParts)} does not meet minimum requirements ${tcbPartsToString(options.minimumTcb)}`);
    }
    if (!tcbMeetsMinimum(reportedTcbParts, options.minimumTcb)) {
      throw new ValidationError(`Reported TCB ${tcbPartsToString(reportedTcbParts)} does not meet minimum requirements ${tcbPartsToString(options.minimumTcb)}`);
    }
  }

  // VCEK-specific TCB check
  chain.validateVcekTcb(tcbFromInt(report.reportedTcb));

  if (options.minimumLaunchTcb) {
    const launchTcbParts = tcbFromInt(report.launchTcb);
    if (!tcbMeetsMinimum(launchTcbParts, options.minimumLaunchTcb)) {
      throw new ValidationError(`Launch TCB ${tcbPartsToString(launchTcbParts)} does not meet minimum requirements ${tcbPartsToString(options.minimumLaunchTcb)}`);
    }
  }

  // Field equality checks
  if (options.reportData) {
    if (report.reportData.length !== 64) {
      throw new ValidationError(`Report data length is ${report.reportData.length}, expected 64 bytes`);
    }
    if (!uint8ArrayEqual(report.reportData, options.reportData)) {
      throw new ValidationError(`Report data mismatch: got ${bytesToHex(report.reportData)}, expected ${bytesToHex(options.reportData)}`);
    }
  }

  if (options.hostData) {
    if (report.hostData.length !== 32) {
      throw new ValidationError(`Host data length is ${report.hostData.length}, expected 32 bytes`);
    }
    if (!uint8ArrayEqual(report.hostData, options.hostData)) {
      throw new ValidationError(`Host data mismatch: got ${bytesToHex(report.hostData)}, expected ${bytesToHex(options.hostData)}`);
    }
  }

  if (options.measurement) {
    if (report.measurement.length !== 48) {
      throw new ValidationError(`Measurement length is ${report.measurement.length}, expected 48 bytes`);
    }
    if (!uint8ArrayEqual(report.measurement, options.measurement)) {
      throw new ValidationError(`Measurement mismatch: got ${bytesToHex(report.measurement)}, expected ${bytesToHex(options.measurement)}`);
    }
  }

  if (options.chipId) {
    if (report.chipId.length !== 64) {
      throw new ValidationError(`Chip ID length is ${report.chipId.length}, expected 64 bytes`);
    }
    if (!uint8ArrayEqual(report.chipId, options.chipId)) {
      throw new ValidationError(`Chip ID mismatch: got ${bytesToHex(report.chipId)}, expected ${bytesToHex(options.chipId)}`);
    }
  }

  if (options.imageId) {
    if (report.imageId.length !== 16) {
      throw new ValidationError(`Image ID length is ${report.imageId.length}, expected 16 bytes`);
    }
    if (!uint8ArrayEqual(report.imageId, options.imageId)) {
      throw new ValidationError(`Image ID mismatch: got ${bytesToHex(report.imageId)}, expected ${bytesToHex(options.imageId)}`);
    }
  }

  if (options.familyId) {
    if (report.familyId.length !== 16) {
      throw new ValidationError(`Family ID length is ${report.familyId.length}, expected 16 bytes`);
    }
    if (!uint8ArrayEqual(report.familyId, options.familyId)) {
      throw new ValidationError(`Family ID mismatch: got ${bytesToHex(report.familyId)}, expected ${bytesToHex(options.familyId)}`);
    }
  }

  if (options.reportId) {
    if (report.reportId.length !== 32) {
      throw new ValidationError(`Report ID length is ${report.reportId.length}, expected 32 bytes`);
    }
    if (!uint8ArrayEqual(report.reportId, options.reportId)) {
      throw new ValidationError(`Report ID mismatch: got ${bytesToHex(report.reportId)}, expected ${bytesToHex(options.reportId)}`);
    }
  }

  if (options.reportIdMa) {
    if (report.reportIdMa.length !== 32) {
      throw new ValidationError(`Report ID MA length is ${report.reportIdMa.length}, expected 32 bytes`);
    }
    if (!uint8ArrayEqual(report.reportIdMa, options.reportIdMa)) {
      throw new ValidationError(`Report ID MA mismatch: got ${bytesToHex(report.reportIdMa)}, expected ${bytesToHex(options.reportIdMa)}`);
    }
  }

  // VCEK-specific CHIP_ID ↔ HWID equality check
  if (report.signerInfoParsed.signingKey === ReportSigner.VcekReportSigner) {
    if (report.signerInfoParsed.maskChipKey && report.chipId.some(b => b !== 0)) {
      throw new ValidationError('maskChipKey is set but CHIP_ID is not zeroed');
    }
    if (!report.signerInfoParsed.maskChipKey) {
      chain.validateVcekHwid(report.chipId);
    }
  }

  // Platform info check
  if (options.platformInfo) {
    validatePlatformInfo(report.platformInfoParsed, options.platformInfo);
  }

  // VMPL check
  if (options.vmpl !== undefined) {
    if (!(0 <= report.vmpl && report.vmpl <= 3)) {
      throw new ValidationError(`VMPL ${report.vmpl} is not in valid range 0-3`);
    }
    if (report.vmpl !== options.vmpl) {
      throw new ValidationError(`VMPL mismatch: got ${report.vmpl}, expected ${options.vmpl}`);
    }
  }

  // Provisional firmware check - we only support permitProvisionalFirmware = false
  if (options.permitProvisionalFirmware) {
    throw new ValidationError('Provisional firmware is not supported');
  }

  // When permitProvisionalFirmware = false, committed and current values must be equal
  if (report.committedBuild !== report.currentBuild) {
    throw new ValidationError(`Committed build ${report.committedBuild} does not match current build ${report.currentBuild}`);
  }
  if (report.committedMinor !== report.currentMinor) {
    throw new ValidationError(`Committed minor version ${report.committedMinor} does not match current minor version ${report.currentMinor}`);
  }
  if (report.committedMajor !== report.currentMajor) {
    throw new ValidationError(`Committed major version ${report.committedMajor} does not match current major version ${report.currentMajor}`);
  }
  if (report.committedTcb !== report.currentTcb) {
    throw new ValidationError(`Committed TCB 0x${report.committedTcb.toString(16)} does not match current TCB 0x${report.currentTcb.toString(16)}`);
  }

  // ID-block / author key requirements
  if (options.requireAuthorKey || options.requireIdBlock) {
    throw new ValidationError('ID-block and author key requirements are not supported yet');
  }
}

/**
 * Validate platform info with security-aware checks.
 *
 * Logic:
 * - If report has a feature enabled that required doesn't allow -> FAIL
 * - If report lacks a feature that required mandates -> FAIL
 *
 * @param reportInfo - Platform info from the attestation report
 * @param required - Required platform info constraints
 * @throws Error if validation fails
 */
function validatePlatformInfo(reportInfo: SnpPlatformInfo, required: SnpPlatformInfo) {
  // Unauthorized features (report has it enabled, but required doesn't allow it)
  if (reportInfo.smtEnabled && !required.smtEnabled) {
    throw new ValidationError(`Unauthorized platform feature SMT enabled. Report platform info: ${JSON.stringify(reportInfo)}, Required platform info: ${JSON.stringify(required)}`);
  }

  // Required features (report lacks something that required mandates)
  if (!reportInfo.eccEnabled && required.eccEnabled) {
    throw new ValidationError(`Required platform feature ECC not enabled. Report platform info: ${JSON.stringify(reportInfo)}, Required platform info: ${JSON.stringify(required)}`);
  }

  if (!reportInfo.tsmeEnabled && required.tsmeEnabled) {
    throw new ValidationError(`Required platform feature TSME not enabled. Report platform info: ${JSON.stringify(reportInfo)}, Required platform info: ${JSON.stringify(required)}`);
  }

  if (!reportInfo.raplDisabled && required.raplDisabled) {
    throw new ValidationError(`Required platform feature RAPL not disabled. Report platform info: ${JSON.stringify(reportInfo)}, Required platform info: ${JSON.stringify(required)}`);
  }

  if (!reportInfo.ciphertextHidingDramEnabled && required.ciphertextHidingDramEnabled) {
    throw new ValidationError(`Required ciphertext hiding in DRAM not enforced. Report platform info: ${JSON.stringify(reportInfo)}, Required platform info: ${JSON.stringify(required)}`);
  }

  if (!reportInfo.aliasCheckComplete && required.aliasCheckComplete) {
    throw new ValidationError(`Required memory alias check hasn't been completed. Report platform info: ${JSON.stringify(reportInfo)}, Required platform info: ${JSON.stringify(required)}`);
  }

  if (!reportInfo.tioEnabled && required.tioEnabled) {
    throw new ValidationError(`Required TIO not enabled. Report platform info: ${JSON.stringify(reportInfo)}, Required platform info: ${JSON.stringify(required)}`);
  }
}