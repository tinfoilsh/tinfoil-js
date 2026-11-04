/**
 * The expected state of an SEV-SNP report, resolved from an endorsed policy
 * at assembly so that validation is one comparison with no lookups. Guest
 * policy and platform info flags must match exactly; levels, versions and
 * mitigation vectors are floors; the identity fields must match verbatim.
 */
import type { Register } from "../../../measurement.js";
import { decodeHex } from "../../policy/artifact.js";
import { validateSevSnpPolicy, type SevSnpPolicy, type Tcb } from "../../policy/sev.js";
import { bytesEqual } from "../../x509/certificate.js";
import type { SevQuote } from "./authenticate.js";
import {
  allZero,
  CHIP_ID_SIZE,
  FAMILY_ID_SIZE,
  HOST_DATA_SIZE,
  IMAGE_ID_SIZE,
  parseGuestPolicy,
  parsePlatformInfo,
  PRODUCT_GENOA,
  PRODUCT_TURIN,
  REPORT_DATA_SIZE,
  type ProductLine,
  type SevReport,
} from "./report.js";
import { composeTcb, decomposeTcb, formatTcb, tcbLayoutOf, tcbLe, type TcbParts } from "./tcb.js";

/** Expectations a policy fixes for a report. */
export interface SevExpectations {
  readonly policy: SevSnpPolicy;
  readonly productLine: ProductLine;
  readonly launch: Register;
  readonly reportData: Uint8Array;
  readonly chipId: Uint8Array;
  /** The 32-byte HOST_DATA the report must carry: the policy's, or for a config-pinned runtime the config hash. */
  readonly hostData: Uint8Array;
  readonly imageId: Uint8Array;
  readonly familyId: Uint8Array;
  readonly minimumTcb: TcbParts;
  readonly minimumLaunchTcb: TcbParts;
  /** major << 8 | minor */
  readonly minimumVersion: number;
  readonly minimumAbiMajor: number;
  readonly minimumAbiMinor: number;
}

/** "maj.min", each a decimal uint8. */
function versionParts(name: string, version: string): { major: number; minor: number } {
  const dot = version.indexOf(".");
  const majorText = dot < 0 ? "" : version.slice(0, dot);
  const minorText = dot < 0 ? "" : version.slice(dot + 1);
  if (!/^[0-9]+$/.test(majorText) || !/^[0-9]+$/.test(minorText)) throw new Error(`${name} ${JSON.stringify(version)} is not maj.min`);
  const major = Number(majorText);
  const minor = Number(minorText);
  if (major > 255) throw new Error(`${name} major: value out of range`);
  if (minor > 255) throw new Error(`${name} minor: value out of range`);
  return { major, minor };
}

function tcbParts(field: string, product: ProductLine, t: Tcb): TcbParts {
  const required = (name: string, v: number | undefined): number => {
    if (v === undefined) throw new Error(`${field}: ${name} is required`);
    return v;
  };
  const parts: TcbParts = {
    layout: tcbLayoutOf(product),
    fmcSpl: t.fmcSpl ?? 0,
    blSpl: required("bl_spl", t.blSpl),
    teeSpl: required("tee_spl", t.teeSpl),
    snpSpl: required("snp_spl", t.snpSpl),
    ucodeSpl: required("ucode_spl", t.ucodeSpl),
    spl4: 0,
    spl5: 0,
    spl6: 0,
    spl7: 0,
  };
  try {
    composeTcb(parts);
  } catch (err) {
    throw new Error(`${field}: ${(err as Error).message}`);
  }
  return parts;
}

/**
 * Builds expectations from a policy: Genoa policies must omit fmc_spl and
 * iommu_write_safe, Turin policies must set both; versions parse as maj.min.
 * `hostData` is the resolved expectation, since a v2 policy declares none.
 */
export function assembleSev(policy: SevSnpPolicy, q: SevQuote, launch: Register, reportData: Uint8Array, hostData: Uint8Array): SevExpectations {
  validateSevSnpPolicy(policy);
  const product = q.productLine;
  switch (product) {
    case PRODUCT_GENOA:
      if (policy.minimumTcb.fmcSpl !== undefined || policy.minimumLaunchTcb.fmcSpl !== undefined) {
        throw new Error(`fmc_spl is not valid for product line ${product}`);
      }
      if (policy.platformInfo.iommuWriteSafe) throw new Error(`iommu_write_safe is not valid for product line ${product}`);
      break;
    case PRODUCT_TURIN:
      if (policy.minimumTcb.fmcSpl === undefined || policy.minimumLaunchTcb.fmcSpl === undefined) {
        throw new Error(`fmc_spl is required for product line ${product}`);
      }
      if (!policy.platformInfo.iommuWriteSafe) throw new Error(`iommu_write_safe is required for product line ${product}`);
      break;
  }
  const api = versionParts("minimum_api_version", policy.minimumApiVersion);
  const abi = versionParts("minimum_abi_version", policy.minimumAbiVersion);
  const minimumTcb = tcbParts("minimum_tcb", product, policy.minimumTcb);
  const minimumLaunchTcb = tcbParts("minimum_launch_tcb", product, policy.minimumLaunchTcb);
  if (launch.length !== 48) throw new Error(`launch measurement must be 48 bytes, got ${launch.length}`);
  if (reportData.length !== REPORT_DATA_SIZE) throw new Error(`REPORT_DATA expectation must be ${REPORT_DATA_SIZE} bytes, got ${reportData.length}`);
  if (hostData.length !== HOST_DATA_SIZE) throw new Error(`HOST_DATA expectation must be ${HOST_DATA_SIZE} bytes, got ${hostData.length}`);
  return {
    policy,
    productLine: product,
    launch: launch.slice(),
    reportData: reportData.slice(),
    chipId: q.report.chipId.slice(),
    hostData: hostData.slice(),
    imageId: decodeHex("image_id", policy.imageId, IMAGE_ID_SIZE),
    familyId: decodeHex("family_id", policy.familyId, FAMILY_ID_SIZE),
    minimumTcb,
    minimumLaunchTcb,
    minimumVersion: (api.major << 8) | api.minor,
    minimumAbiMajor: abi.major,
    minimumAbiMinor: abi.minor,
  };
}

function checkVerbatim(field: string, got: Uint8Array, want: Uint8Array, size: number): void {
  if (want.length !== size) throw new Error(`expectation ${field} must be ${size} bytes`);
  if (!bytesEqual(got, want)) throw new Error(`report field ${field} does not match the expected value`);
}

/** Decomposes the report's TCB fields and the VCEK's under the product's layout and checks their order against the policy floors. */
function checkTcb(e: SevExpectations, q: SevQuote): void {
  const layout = tcbLayoutOf(e.productLine);
  const r = q.report;
  const parts = (name: string, tcb: bigint): TcbParts => {
    try {
      return decomposeTcb(layout, tcb);
    } catch (err) {
      throw new Error(`report's ${name}: ${(err as Error).message}`);
    }
  };
  const reported = parts("REPORTED_TCB", r.reportedTcb);
  const current = parts("CURRENT_TCB", r.currentTcb);
  const committed = parts("COMMITTED_TCB", r.committedTcb);
  const launch = parts("LAUNCH_TCB", r.launchTcb);
  const cert = q.vcek.tcb;
  if (cert.layout !== layout) throw new Error(`report product ${JSON.stringify(e.productLine)} and VCEK certificate use different TCB formats`);

  const equal = (a: TcbParts, aName: string, b: TcbParts, bName: string): void => {
    let ca: bigint;
    let cb: bigint;
    try {
      ca = composeTcb(a);
      cb = composeTcb(b);
    } catch (err) {
      throw new Error(`could not compare TCB values: ${(err as Error).message}`);
    }
    if (ca !== cb) throw new Error(`the ${aName} ${formatTcb(a)} does not match the ${bName} ${formatTcb(b)}`);
  };
  const atMost = (lower: TcbParts, lowerName: string, higher: TcbParts, higherName: string): void => {
    if (!tcbLe(lower, higher)) {
      throw new Error(`the ${higherName} ${formatTcb(higher)} is lower than the ${lowerName} ${formatTcb(lower)} in at least one component`);
    }
  };
  if (e.policy.permitProvisionalFirmware) atMost(committed, "report's COMMITTED_TCB", current, "report's CURRENT_TCB");
  else equal(committed, "report's COMMITTED_TCB", current, "report's CURRENT_TCB");
  atMost(e.minimumLaunchTcb, "policy minimum launch TCB", launch, "report's LAUNCH_TCB");
  // The VCEK endorses exactly the reported TCB; a certificate for another
  // level, higher or lower, is not the certificate for this machine state.
  equal(reported, "report's REPORTED_TCB", cert, "TCB of the VCEK certificate");
  atMost(cert, "TCB of the VCEK certificate", current, "report's CURRENT_TCB");
  atMost(e.minimumTcb, "policy minimum TCB", reported, "report's REPORTED_TCB");
}

function checkVersion(e: SevExpectations, r: SevReport): void {
  const minimumBuild = e.policy.minimumBuild ?? 0;
  if (minimumBuild > r.currentBuild) {
    throw new Error(`firmware build number ${r.currentBuild} is less than the required minimum ${minimumBuild}`);
  }
  const current = (r.currentMajor << 8) | r.currentMinor;
  if (e.minimumVersion > current) {
    throw new Error(
      `firmware API version (${r.currentMajor}.${r.currentMinor}) is less than the required minimum (${e.minimumVersion >> 8}.${e.minimumVersion & 0xff})`,
    );
  }
  const committed = (r.committedMajor << 8) | r.committedMinor;
  if (!e.policy.permitProvisionalFirmware) {
    if (r.committedBuild !== r.currentBuild) {
      throw new Error(`committed build number ${r.committedBuild} does not match the current build number ${r.currentBuild}`);
    }
    if (committed !== current) {
      throw new Error(
        `committed API version (${r.committedMajor}.${r.committedMinor}) does not match the current API version (${r.currentMajor}.${r.currentMinor})`,
      );
    }
  } else {
    if (r.committedBuild > r.currentBuild) {
      throw new Error(`committed build number ${r.committedBuild} is greater than the current build number ${r.currentBuild}`);
    }
    if (committed > current) {
      throw new Error(
        `committed API version (${r.committedMajor}.${r.committedMinor}) is greater than the current API version (${r.currentMajor}.${r.currentMinor})`,
      );
    }
  }
}

/** The report must be launched without an author key or ID block, under an unmasked CHIP_ID. */
function checkSigner(r: SevReport): void {
  if (r.signer.maskChipKey) throw new Error("report masks CHIP_ID; masked platform identities are unsupported");
  if (r.signer.authorKeyEn) throw new Error("report carries an author key; ID-block launches are unsupported");
  if (!allZero(r.idKeyDigest)) throw new Error("report carries an ID block; ID-block launches are unsupported");
  if (!allZero(r.authorKeyDigest)) throw new Error("report carries an author key digest; ID-block launches are unsupported");
}

/** An unmasked CHIP_ID must equal the VCEK's hardware id (its first 8 bytes under TCB layout 1). */
function checkHwid(r: SevReport, hwid: Uint8Array): void {
  if (allZero(r.chipId)) return;
  let reportHwid: Uint8Array;
  switch (hwid.length) {
    case CHIP_ID_SIZE:
      reportHwid = r.chipId;
      break;
    case 8:
      reportHwid = r.chipId.subarray(0, 8);
      break;
    default:
      throw new Error(`VCEK certificate HWID has unsupported size ${hwid.length}`);
  }
  if (!bytesEqual(reportHwid, hwid)) throw new Error("report field CHIP_ID is not the same as the VCEK certificate's HWID");
}

/**
 * Validates the report against the expectations: guest policy and platform
 * info bits exactly, minimum build/version/SVN/TCBs, VMPL, host data, image
 * and family ids, mitigation vectors, measurement, report data and chip id,
 * the VCEK's hardware id, and that no author key or id block signed the launch.
 */
export function validateSev(e: SevExpectations, q: SevQuote): void {
  const r = q.report;
  const p = e.policy;
  const minimumGuestSvn = p.minimumGuestSvn ?? 0;
  if (r.guestSvn < minimumGuestSvn) throw new Error(`report's GUEST_SVN ${r.guestSvn} is less than the required minimum ${minimumGuestSvn}`);

  const got = parseGuestPolicy(r.policy);
  const minimumAbi = (e.minimumAbiMajor << 8) | e.minimumAbiMinor;
  if (minimumAbi > ((got.abiMajor << 8) | got.abiMinor)) {
    throw new Error(
      `required policy ABI version (${e.minimumAbiMajor}.${e.minimumAbiMinor}) is greater than the report's ABI version (${got.abiMajor}.${got.abiMinor})`,
    );
  }
  const g = p.guestPolicy;
  if (
    got.debug !== g.debug ||
    got.smt !== g.smt ||
    got.migrateMa !== g.migrateMa ||
    got.singleSocket !== g.singleSocket ||
    got.cxlAllowed !== g.cxlAllowed ||
    got.memAes256Xts !== g.memAes256Xts ||
    got.raplDis !== g.raplDis ||
    got.ciphertextHidingDram !== g.ciphertextHidingDram ||
    got.pageSwapDisable !== g.pageSwapDisable
  ) {
    throw new Error("SEV report guest policy does not match the endorsed policy");
  }

  checkVerbatim("REPORT_DATA", r.reportData, e.reportData, REPORT_DATA_SIZE);
  checkVerbatim("HOST_DATA", r.hostData, e.hostData, HOST_DATA_SIZE);
  checkVerbatim("FAMILY_ID", r.familyId, e.familyId, FAMILY_ID_SIZE);
  checkVerbatim("IMAGE_ID", r.imageId, e.imageId, IMAGE_ID_SIZE);
  checkVerbatim("MEASUREMENT", r.measurement, e.launch, 48);
  checkVerbatim("CHIP_ID", r.chipId, e.chipId, CHIP_ID_SIZE);

  checkTcb(e, q);
  checkVersion(e, r);

  const info = parsePlatformInfo(r.platformInfo);
  const want = p.platformInfo;
  if (
    info.smtEnabled !== want.smtEnabled ||
    info.tsmeEnabled !== want.tsmeEnabled ||
    info.eccEnabled !== want.eccEnabled ||
    info.raplDisabled !== want.raplDisabled ||
    info.ciphertextHidingDram !== want.ciphertextHidingDram ||
    info.aliasCheckComplete !== want.aliasCheckComplete ||
    info.iommuWriteSafe !== want.iommuWriteSafe ||
    info.tioEnabled !== want.tioEnabled
  ) {
    throw new Error("SEV report PLATFORM_INFO does not match the endorsed policy");
  }

  const minLaunchMit = p.minimumLaunchMitigationVector ?? 0n;
  if ((r.launchMitVector & minLaunchMit) !== minLaunchMit) {
    throw new Error(`launch mitigation vector (0x${r.launchMitVector.toString(16)}) is missing required bits; expected at least (0x${minLaunchMit.toString(16)})`);
  }
  const minCurrentMit = p.minimumCurrentMitigationVector ?? 0n;
  if ((r.currentMitVector & minCurrentMit) !== minCurrentMit) {
    throw new Error(`current mitigation vector (0x${r.currentMitVector.toString(16)}) is missing required bits; expected at least (0x${minCurrentMit.toString(16)})`);
  }

  if (p.vmpl === undefined || BigInt(r.vmpl) !== p.vmpl) throw new Error(`report VMPL ${r.vmpl} is not ${p.vmpl}`);
  checkHwid(r, q.vcek.hwid);
  checkSigner(r);
}
