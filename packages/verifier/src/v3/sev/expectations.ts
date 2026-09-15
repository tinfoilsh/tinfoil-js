// SEV-SNP policy translation and quote validation, a 1:1 port of Go
// verifier/quote/sev/expectations.go plus the checks the assembled
// go-sev-guest validate.SnpAttestation options perform. Every rejection
// throws VerificationError("POLICY_REJECTED", ...).

import { bytesEqual, decodeHex, encodeHex } from "../bytes.js";
import { VerificationError } from "../errors.js";
import { decodeHexPolicy, validateSEVSNPPolicy, type SEVSNPPolicy, type TCB } from "../policy.js";
import {
  decomposeTCB,
  newTCBParts,
  parseSignerInfo,
  parseSnpPlatformInfo,
  parseSnpPolicy,
  productLineFromFms,
  productLineToTCBVersion,
  TcbStructVersion0,
  tcbPartsLE,
  tcbPartsToVersion,
  VcekReportSigner,
  type SevReport,
  type SnpPlatformInfo,
  type SnpPolicy,
  type TCBParts,
} from "./abi.js";
import { ProductGenoa, ProductTurin, rejectMaskedChipID, type SevQuote } from "./authenticate.js";
import { certificateExtensions } from "./kds.js";

function policyError(message: string): VerificationError {
  return new VerificationError("POLICY_REJECTED", message);
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// SevValidateOptions mirrors the go-sev-guest validate.Options fields the
// verifier sets; unset library options (report_id, report_id_ma, ID-block
// trust) are deliberately absent and never enforced.
interface SevValidateOptions {
  guestPolicy: SnpPolicy; // maximum-acceptable mask, ABI version floor
  minimumGuestSvn: number;
  minimumBuild: number;
  minimumVersion: number; // maj<<8 | min
  permitProvisionalFirmware: boolean;
  platformInfo: SnpPlatformInfo; // maximum-acceptable mask
  minimumTCB: TCBParts;
  minimumLaunchTCB: TCBParts;
  vmpl: number;
  hostData: Uint8Array;
  imageID: Uint8Array;
  familyID: Uint8Array;
  minimumLaunchMitigationVector: bigint;
  minimumCurrentMitigationVector: bigint;
  measurement: Uint8Array;
  reportData: Uint8Array;
  chipID: Uint8Array;
}

// SevExpectations is the fully translated SEV-SNP expected state, resolved
// at assembly so validation performs no translation and no lookups. The
// want* fields are compared by strict equality — the library options only
// bound them (Go sev.Expectations).
export interface SevExpectations {
  opts: SevValidateOptions;
  wantGuestPolicy: SnpPolicy;
  wantPlatformInfo: SnpPlatformInfo;
}

function expectedGuestPolicy(p: SEVSNPPolicy): SnpPolicy {
  return {
    abiMajor: 0,
    abiMinor: 0,
    debug: p.guestPolicy.debug,
    smt: p.guestPolicy.smt,
    migrateMA: p.guestPolicy.migrateMA,
    singleSocket: p.guestPolicy.singleSocket,
    cxlAllowed: p.guestPolicy.cxlAllowed,
    memAES256XTS: p.guestPolicy.memAES256XTS,
    raplDis: p.guestPolicy.raplDis,
    cipherTextHidingDRAM: p.guestPolicy.ciphertextHidingDRAM,
    pageSwapDisable: p.guestPolicy.pageSwapDisable,
  };
}

function expectedPlatformInfo(p: SEVSNPPolicy): SnpPlatformInfo {
  return {
    smtEnabled: p.platformInfo.smtEnabled,
    tsmeEnabled: p.platformInfo.tsmeEnabled,
    eccEnabled: p.platformInfo.eccEnabled,
    raplDisabled: p.platformInfo.raplDisabled,
    ciphertextHidingDRAMEnabled: p.platformInfo.ciphertextHidingDRAM,
    aliasCheckComplete: p.platformInfo.aliasCheckComplete,
    iommuWriteSafe: p.platformInfo.iommuWriteSafe,
    tioEnabled: p.platformInfo.tioEnabled,
  };
}

function parseVersionParts(name: string, v: string): { maj: number; min: number } {
  const dot = v.indexOf(".");
  if (dot < 0) {
    throw policyError(`${name} ${JSON.stringify(v)} is not maj.min`);
  }
  const parse = (part: string, label: string): number => {
    if (!/^[0-9]+$/.test(part)) throw policyError(`${name} ${label}: invalid syntax`);
    const n = parseInt(part, 10);
    if (n > 255) throw policyError(`${name} ${label}: value out of range`);
    return n;
  };
  return { maj: parse(v.slice(0, dot), "major"), min: parse(v.slice(dot + 1), "minor") };
}

// tcbParts translates a policy TCB block into layout-tagged parts for the
// product line (Go tcbParts + kds.NewTCBParts).
function tcbParts(field: string, productLine: string, t: TCB): TCBParts {
  try {
    return newTCBParts(productLine, {
      fmcSpl: t.fmcSpl ?? 0,
      blSpl: t.blSpl ?? 0,
      teeSpl: t.teeSpl ?? 0,
      snpSpl: t.snpSpl ?? 0,
      ucodeSpl: t.ucodeSpl ?? 0,
    });
  } catch (err) {
    throw policyError(`${field}: ${errMsg(err)}`);
  }
}

// options translates the policy block into validation options for the given
// product line. GuestPolicy and PlatformInfo are maximum-acceptable masks;
// strict equality on both is enforced by the companion checks composed in
// sevValidate (Go options).
function options(p: SEVSNPPolicy, productLine: string): Omit<SevValidateOptions, "measurement" | "reportData" | "chipID"> {
  const invalid = validateSEVSNPPolicy(p);
  if (invalid !== undefined) {
    throw policyError(invalid);
  }
  // Per-product rules: Turin adds fmc_spl and requires PLATFORM_INFO bit 6
  // (iommu_write_safe); Genoa forbids both (Go options).
  if (productLine === ProductGenoa) {
    if (p.minimumTCB.fmcSpl !== undefined || p.minimumLaunchTCB.fmcSpl !== undefined) {
      throw policyError(`fmc_spl is not valid for product line ${productLine}`);
    }
    if (p.platformInfo.iommuWriteSafe) {
      throw policyError(`iommu_write_safe is not valid for product line ${productLine}`);
    }
  } else if (productLine === ProductTurin) {
    if (p.minimumTCB.fmcSpl === undefined || p.minimumLaunchTCB.fmcSpl === undefined) {
      throw policyError(`fmc_spl is required for product line ${productLine}`);
    }
    if (!p.platformInfo.iommuWriteSafe) {
      throw policyError(`iommu_write_safe is required for product line ${productLine}`);
    }
  } else {
    throw policyError(`unsupported SEV product line ${JSON.stringify(productLine)}`);
  }
  const api = parseVersionParts("minimum_api_version", p.minimumAPIVersion);
  const abi = parseVersionParts("minimum_abi_version", p.minimumABIVersion);
  let hostData: Uint8Array;
  let imageID: Uint8Array;
  let familyID: Uint8Array;
  try {
    hostData = decodeHexPolicy("host_data", p.hostData, 32);
    imageID = decodeHexPolicy("image_id", p.imageID, 16);
    familyID = decodeHexPolicy("family_id", p.familyID, 16);
  } catch (err) {
    throw policyError(errMsg(err));
  }

  // The ABI floor rides in the guest policy: it is compared as a minimum
  // version, unlike the other bits.
  const guestPolicy = expectedGuestPolicy(p);
  guestPolicy.abiMajor = abi.maj;
  guestPolicy.abiMinor = abi.min;
  return {
    guestPolicy,
    minimumGuestSvn: p.minimumGuestSVN!,
    minimumBuild: p.minimumBuild!,
    minimumVersion: (api.maj << 8) | api.min,
    permitProvisionalFirmware: p.permitProvisionalFirmware,
    platformInfo: expectedPlatformInfo(p),
    minimumTCB: tcbParts("minimum_tcb", productLine, p.minimumTCB),
    minimumLaunchTCB: tcbParts("minimum_launch_tcb", productLine, p.minimumLaunchTCB),
    vmpl: p.vmpl!,
    hostData,
    imageID,
    familyID,
    minimumLaunchMitigationVector: BigInt(p.minimumLaunchMitigationVector!),
    minimumCurrentMitigationVector: BigInt(p.minimumCurrentMitigationVector!),
  };
}

// sevAssemble translates a policy block into the complete expected state
// for the quote: validation options carrying every policy field, the
// expected launch measurement, the expected REPORT_DATA, and the endorsed
// CHIP_ID the policy was selected by. Only Genoa is supported (Go Assemble).
export function sevAssemble(
  p: SEVSNPPolicy,
  q: SevQuote,
  launchDigest: Uint8Array,
  reportData: Uint8Array,
): SevExpectations {
  const base = options(p, q.productLine);
  if (launchDigest.length !== 48) {
    throw policyError(`expected launch digest must be 48 bytes, got ${launchDigest.length}`);
  }
  if (reportData.length !== 64) {
    throw policyError(`expected report data must be 64 bytes, got ${reportData.length}`);
  }
  let chipID: Uint8Array;
  try {
    chipID = decodeHex(q.identity);
  } catch (err) {
    throw policyError(`decoding platform identity: ${errMsg(err)}`);
  }
  return {
    opts: { ...base, measurement: launchDigest, reportData, chipID },
    wantGuestPolicy: expectedGuestPolicy(p),
    wantPlatformInfo: expectedPlatformInfo(p),
  };
}

// Library validation (go-sev-guest validate.SnpAttestation with the
// assembled options; unset options' checks omitted).

const versionValue = (major: number, minor: number): number => (major << 8) | minor;

// validatePolicy bounds the report's guest policy by the required mask and
// enforces the ABI version floor (Go validate.validatePolicy).
function validatePolicy(reportPolicy: bigint, required: SnpPolicy): void {
  let policy: SnpPolicy;
  try {
    policy = parseSnpPolicy(reportPolicy);
  } catch (err) {
    throw policyError(`could not parse SNP policy: ${errMsg(err)}`);
  }
  if (versionValue(required.abiMajor, required.abiMinor) > versionValue(policy.abiMajor, policy.abiMinor)) {
    throw policyError(
      `required policy ABI version (${required.abiMajor}.${required.abiMinor}) is greater than the report's ABI version (${policy.abiMajor}.${policy.abiMinor})`,
    );
  }
  if (!required.migrateMA && policy.migrateMA) {
    throw policyError("found unauthorized migration agent capability");
  }
  if (!required.debug && policy.debug) {
    throw policyError("found unauthorized debug capability");
  }
  if (!required.smt && policy.smt) {
    throw policyError("found unauthorized symmetric multithreading (SMT) capability");
  }
  if (required.singleSocket && !policy.singleSocket) {
    throw policyError("required single socket restriction not present");
  }
  if (!required.cxlAllowed && policy.cxlAllowed) {
    throw policyError("found unauthorized CXL capability");
  }
  if (required.memAES256XTS && !policy.memAES256XTS) {
    throw policyError("found unauthorized memory encryption mode");
  }
  if (required.raplDis && !policy.raplDis) {
    throw policyError("found unauthorized RAPL capability");
  }
  if (required.cipherTextHidingDRAM && !policy.cipherTextHidingDRAM) {
    throw policyError("ciphertext hiding in DRAM isn't enforced");
  }
  if (required.pageSwapDisable && !policy.pageSwapDisable) {
    throw policyError("found unauthorized page swap capability");
  }
}

function validateByteField(field: string, given: Uint8Array, required: Uint8Array): void {
  if (!bytesEqual(required, given)) {
    throw policyError(`report field ${field} is ${encodeHex(given)}. Expect ${encodeHex(required)}`);
  }
}

// validateVerbatimFields compares the exact-match fields the options set;
// REPORT_ID and REPORT_ID_MA are unset and never enforced (Go
// validate.validateVerbatimFields).
function validateVerbatimFields(report: SevReport, opts: SevValidateOptions): void {
  validateByteField("REPORT_DATA", report.reportData, opts.reportData);
  validateByteField("HOST_DATA", report.hostData, opts.hostData);
  validateByteField("FAMILY_ID", report.familyId, opts.familyID);
  validateByteField("IMAGE_ID", report.imageId, opts.imageID);
  validateByteField("MEASUREMENT", report.measurement, opts.measurement);
  validateByteField("CHIP_ID", report.chipId, opts.chipID);
}

function tcbNeError(leftDesc: string, left: TCBParts, rightDesc: string, right: TCBParts): void {
  let ltcb: { structVersion: number; tcb: bigint };
  let rtcb: { structVersion: number; tcb: bigint };
  try {
    ltcb = tcbPartsToVersion(left);
    rtcb = tcbPartsToVersion(right);
  } catch (err) {
    throw policyError(`could not compare TCB values: ${errMsg(err)}`);
  }
  if (ltcb.structVersion !== rtcb.structVersion || ltcb.tcb !== rtcb.tcb) {
    throw policyError(
      `the ${leftDesc} 0x${ltcb.tcb.toString(16)} does not match the ${rightDesc} 0x${rtcb.tcb.toString(16)}`,
    );
  }
}

// tcbGtError enforces wantLower <= wantHigher component-wise.
function tcbGtError(lowerDesc: string, wantLower: TCBParts, higherDesc: string, wantHigher: TCBParts): void {
  if (!tcbPartsLE(wantLower, wantHigher)) {
    throw policyError(`the ${higherDesc} is lower than the ${lowerDesc} in at least one component`);
  }
}

// getReportTcbs decomposes the report and certificate TCBs under the product's
// layout (Go validate.getReportTcbs): [reported, current, committed, launch,
// cert].
function getReportTcbs(
  report: SevReport,
  certTcbVersion: number,
  certTcb: bigint,
): [TCBParts, TCBParts, TCBParts, TCBParts, TCBParts] {
  let layout: number;
  if (report.version >= 3) {
    const productLine = productLineFromFms(report.cpuid1EaxFms);
    try {
      layout = productLineToTCBVersion(productLine);
    } catch (err) {
      throw policyError(`could not determine report TCB format: ${errMsg(err)}`);
    }
    if (layout !== certTcbVersion) {
      throw policyError(`report product "${productLine}" and V[CL]EK certificate use different TCB formats`);
    }
  } else {
    // Pre-v3 reports predate the Turin TCB layout; do not let a version-1
    // certificate reinterpret their TCB fields.
    layout = TcbStructVersion0;
    if (certTcbVersion !== layout) {
      throw policyError(`report version ${report.version} cannot be used with a non-legacy TCB format`);
    }
  }
  try {
    return [
      decomposeTCB(layout, report.reportedTcb),
      decomposeTCB(layout, report.currentTcb),
      decomposeTCB(layout, report.committedTcb),
      decomposeTCB(layout, report.launchTcb),
      decomposeTCB(certTcbVersion, certTcb),
    ];
  } catch (err) {
    throw policyError(errMsg(err));
  }
}

// validateTcb enforces the report/certificate TCB relationships (Go
// validate.validateTcb): COMMITTED vs CURRENT, the launch and reported
// floors, REPORTED == certificate TCB, and certificate TCB <= CURRENT.
function validateTcb(report: SevReport, certTcbVersion: number, certTcb: bigint, opts: SevValidateOptions): void {
  const [reported, current, committed, launch, cert] = getReportTcbs(report, certTcbVersion, certTcb);

  if (opts.permitProvisionalFirmware) {
    tcbGtError("report's COMMITTED_TCB", committed, "report's CURRENT_TCB", current);
  } else {
    tcbNeError("report's COMMITTED_TCB", committed, "report's CURRENT_TCB", current);
  }
  tcbGtError("policy minimum launch TCB", opts.minimumLaunchTCB, "report's LAUNCH_TCB", launch);
  tcbNeError("report's REPORTED_TCB", reported, "TCB of the V[CL]EK certificate", cert);
  tcbGtError("TCB of the V[CL]EK certificate", cert, "report's CURRENT_TCB", current);
  tcbGtError("policy minimum TCB", opts.minimumTCB, "report's REPORTED_TCB", reported);
}

// validateVersion enforces the firmware build/version floors and the
// committed/current relationship (Go validate.validateVersion).
function validateVersion(report: SevReport, opts: SevValidateOptions): void {
  if (opts.minimumBuild > report.currentBuild) {
    throw policyError(`firmware build number ${report.currentBuild} is less than the required minimum ${opts.minimumBuild}`);
  }
  if (opts.minimumVersion > versionValue(report.currentMajor, report.currentMinor)) {
    throw policyError(
      `firmware API version (${report.currentMajor}.${report.currentMinor}) is less than the required minimum (${opts.minimumVersion >> 8}.${opts.minimumVersion & 0xff})`,
    );
  }
  const buildCmp = report.committedBuild - report.currentBuild;
  const versionCmp =
    versionValue(report.committedMajor, report.committedMinor) - versionValue(report.currentMajor, report.currentMinor);
  if (!opts.permitProvisionalFirmware) {
    if (buildCmp !== 0) {
      throw policyError(
        `committed build number ${report.committedBuild} does not match the current build number ${report.currentBuild}`,
      );
    }
    if (versionCmp !== 0) {
      throw policyError(
        `committed API version (${report.committedMajor}.${report.committedMinor}) does not match the current API version (${report.currentMajor}.${report.currentMinor})`,
      );
    }
  } else {
    if (buildCmp > 0) {
      throw policyError(
        `committed build number ${report.committedBuild} is greater than the current build number ${report.currentBuild}`,
      );
    }
    if (versionCmp > 0) {
      throw policyError(
        `committed API version (${report.committedMajor}.${report.committedMinor}) is greater than the current API version`,
      );
    }
  }
}

// validatePlatformInfo bounds the report's PLATFORM_INFO by the required
// mask (Go validate.validatePlatformInfo).
function validatePlatformInfo(platformInfo: bigint, required: SnpPlatformInfo): void {
  let reportInfo: SnpPlatformInfo;
  try {
    reportInfo = parseSnpPlatformInfo(platformInfo);
  } catch (err) {
    throw policyError(`could not parse SNP platform info ${platformInfo.toString(16)}: ${errMsg(err)}`);
  }
  if (reportInfo.smtEnabled && !required.smtEnabled) {
    throw policyError("unauthorized platform feature SMT enabled");
  }
  if (reportInfo.tsmeEnabled && !required.tsmeEnabled) {
    throw policyError("unauthorized platform feature TSME enabled");
  }
  if (!reportInfo.eccEnabled && required.eccEnabled) {
    throw policyError("required platform feature ECC not enabled");
  }
  if (!reportInfo.raplDisabled && required.raplDisabled) {
    throw policyError("unauthorized platform feature RAPL enabled");
  }
  if (!reportInfo.ciphertextHidingDRAMEnabled && required.ciphertextHidingDRAMEnabled) {
    throw policyError("required ciphertext hiding in DRAM not enforced");
  }
  if (!reportInfo.aliasCheckComplete && required.aliasCheckComplete) {
    throw policyError("required memory alias check hasn't been completed");
  }
  if (!reportInfo.iommuWriteSafe && required.iommuWriteSafe) {
    throw policyError("required IOMMU write-safe hardware mitigation is not present");
  }
  if (reportInfo.tioEnabled && !required.tioEnabled) {
    throw policyError("unauthorized feature SEV-TIO enabled");
  }
}

// validateMitigationVectors requires the report's vectors to be supersets
// of the minimums (Go validate.validateMitigationVectors).
function validateMitigationVectors(report: SevReport, opts: SevValidateOptions): void {
  if ((report.launchMitVector & opts.minimumLaunchMitigationVector) !== opts.minimumLaunchMitigationVector) {
    throw policyError(
      `launch mitigation vector (0x${report.launchMitVector.toString(16)}) is missing required bits; expected at least (0x${opts.minimumLaunchMitigationVector.toString(16)})`,
    );
  }
  if ((report.currentMitVector & opts.minimumCurrentMitigationVector) !== opts.minimumCurrentMitigationVector) {
    throw policyError(
      `current mitigation vector (0x${report.currentMitVector.toString(16)}) is missing required bits; expected at least (0x${opts.minimumCurrentMitigationVector.toString(16)})`,
    );
  }
}

function allZero(buf: Uint8Array): boolean {
  for (const b of buf) if (b !== 0) return false;
  return true;
}

// snpAttestationValidate mirrors validate.SnpAttestation for the assembled
// options. RequireAuthorKey/RequireIDBlock are always false (validateKeys
// no-op) and no cert-table options are set.
function snpAttestationValidate(q: SevQuote, opts: SevValidateOptions): void {
  const report = q.report;
  let info;
  try {
    info = parseSignerInfo(report.signerInfo);
  } catch (err) {
    throw policyError(errMsg(err));
  }
  let exts;
  try {
    exts = certificateExtensions(q.vcek, info.signingKey);
  } catch (err) {
    throw policyError(`could not get ${info.signingKey} certificate extensions: ${errMsg(err)}`);
  }

  if (report.guestSvn < opts.minimumGuestSvn) {
    throw policyError(`report's GUEST_SVN ${report.guestSvn} is less than the required minimum ${opts.minimumGuestSvn}`);
  }

  validatePolicy(report.policy, opts.guestPolicy);
  validateVerbatimFields(report, opts);
  validateTcb(report, exts.tcbStructVersion, exts.tcbVersion, opts);
  validateVersion(report, opts);
  validatePlatformInfo(report.platformInfo, opts.platformInfo);
  validateMitigationVectors(report, opts);

  if (opts.vmpl !== report.vmpl) {
    throw policyError(`report VMPL ${report.vmpl} is not ${opts.vmpl}`);
  }

  // MaskChipId might be 1 for the host, so an all-zero report CHIP_ID is
  // permitted here; otherwise bind it to the product-specific VCEK HWID.
  if (info.signingKey === VcekReportSigner) {
    validateVCEKChipID(report.chipId, exts.hwid);
  }
}

// validateVCEKChipID binds a non-zero report CHIP_ID to the product-specific
// VCEK HWID: 64 bytes for Genoa, an 8-byte PSN-based prefix for Turin (Go
// validate.validateVCEKChipID).
function validateVCEKChipID(reportChipID: Uint8Array, certificateHwid: Uint8Array | undefined): void {
  if (reportChipID.length !== 64) {
    throw policyError(`report field CHIP_ID has size ${reportChipID.length}, want 64`);
  }
  if (allZero(reportChipID)) {
    return;
  }
  const hwid = certificateHwid ?? new Uint8Array(0);
  let reportHwid: Uint8Array;
  if (hwid.length === 64) {
    reportHwid = reportChipID;
  } else if (hwid.length === 8) {
    // Turin and later use an 8-byte PSN-based HWID.
    reportHwid = reportChipID.subarray(0, 8);
  } else {
    throw policyError(`VCEK certificate HWID has unsupported size ${hwid.length}`);
  }
  if (!bytesEqual(reportHwid, hwid)) {
    throw policyError(
      `report field CHIP_ID ${encodeHex(reportHwid)} is not the same as the VCEK certificate's HWID ${encodeHex(hwid)}`,
    );
  }
}

function snpPolicyEqual(a: SnpPolicy, b: SnpPolicy): boolean {
  return (
    a.abiMajor === b.abiMajor &&
    a.abiMinor === b.abiMinor &&
    a.smt === b.smt &&
    a.migrateMA === b.migrateMA &&
    a.debug === b.debug &&
    a.singleSocket === b.singleSocket &&
    a.cxlAllowed === b.cxlAllowed &&
    a.memAES256XTS === b.memAES256XTS &&
    a.raplDis === b.raplDis &&
    a.cipherTextHidingDRAM === b.cipherTextHidingDRAM &&
    a.pageSwapDisable === b.pageSwapDisable
  );
}

function snpPlatformInfoEqual(a: SnpPlatformInfo, b: SnpPlatformInfo): boolean {
  return (
    a.smtEnabled === b.smtEnabled &&
    a.tsmeEnabled === b.tsmeEnabled &&
    a.eccEnabled === b.eccEnabled &&
    a.raplDisabled === b.raplDisabled &&
    a.ciphertextHidingDRAMEnabled === b.ciphertextHidingDRAMEnabled &&
    a.aliasCheckComplete === b.aliasCheckComplete &&
    a.iommuWriteSafe === b.iommuWriteSafe &&
    a.tioEnabled === b.tioEnabled
  );
}

// checkSigner requires the report to be launched without an author key or
// ID block: ID-block launches are unsupported (policy parsing rejects
// require_* flags), and the library options cannot require absence (Go
// checkSigner).
function checkSigner(report: SevReport): void {
  try {
    rejectMaskedChipID(report);
  } catch (err) {
    throw policyError(errMsg(err));
  }
  let signer;
  try {
    signer = parseSignerInfo(report.signerInfo);
  } catch (err) {
    throw policyError(`parsing report SIGNER_INFO: ${errMsg(err)}`);
  }
  if (signer.authorKeyEn) {
    throw policyError("report carries an author key; ID-block launches are unsupported");
  }
  if (!allZero(report.idKeyDigest)) {
    throw policyError("report carries an ID block; ID-block launches are unsupported");
  }
  if (!allZero(report.authorKeyDigest)) {
    throw policyError("report carries an author key digest; ID-block launches are unsupported");
  }
}

// sevValidate compares a quote against the assembled expected state: the
// library validation options plus the strict-equality companions. It is
// the only SEV enforcement entry point, so no subset of the policy can be
// applied (Go Expectations.Validate).
export function sevValidate(e: SevExpectations, q: SevQuote): void {
  snpAttestationValidate(q, e.opts);

  const report = q.report;
  let gotPolicy: SnpPolicy;
  try {
    gotPolicy = parseSnpPolicy(report.policy);
  } catch (err) {
    throw policyError(`parsing report guest policy: ${errMsg(err)}`);
  }
  // ABI major/minor are a version floor (minimum_abi_version), enforced by
  // the library's guest-policy comparison, not exact bits.
  const wantPolicy: SnpPolicy = { ...e.wantGuestPolicy, abiMajor: gotPolicy.abiMajor, abiMinor: gotPolicy.abiMinor };
  if (!snpPolicyEqual(gotPolicy, wantPolicy)) {
    throw policyError("report guest policy does not equal the endorsed policy");
  }

  let gotInfo: SnpPlatformInfo;
  try {
    gotInfo = parseSnpPlatformInfo(report.platformInfo);
  } catch (err) {
    throw policyError(`parsing report PLATFORM_INFO: ${errMsg(err)}`);
  }
  if (!snpPlatformInfoEqual(gotInfo, e.wantPlatformInfo)) {
    throw policyError("report PLATFORM_INFO does not equal the endorsed policy");
  }

  checkSigner(report);
}
