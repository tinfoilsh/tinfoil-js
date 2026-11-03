import { bool, int64, object, str, struct, uint } from "../../internal/json/decode.js";
import type { JsonObject, JsonValue } from "../../internal/json/index.js";
import { validatePolicyHex } from "./tdx.js";

/** AMD security patch levels, each an optional uint8. FMC is Turin-only. */
export interface Tcb {
  readonly fmcSpl?: number;
  readonly blSpl?: number;
  readonly teeSpl?: number;
  readonly snpSpl?: number;
  readonly ucodeSpl?: number;
}

/** Expected SEV-SNP guest policy bits. */
export interface GuestPolicy {
  readonly debug: boolean;
  readonly smt: boolean;
  readonly migrateMa: boolean;
  readonly singleSocket: boolean;
  readonly cxlAllowed: boolean;
  readonly memAes256Xts: boolean;
  readonly raplDis: boolean;
  readonly ciphertextHidingDram: boolean;
  readonly pageSwapDisable: boolean;
}

/** Expected PLATFORM_INFO bits. */
export interface SnpPlatform {
  readonly smtEnabled: boolean;
  readonly tsmeEnabled: boolean;
  readonly eccEnabled: boolean;
  readonly raplDisabled: boolean;
  readonly ciphertextHidingDram: boolean;
  readonly aliasCheckComplete: boolean;
  readonly iommuWriteSafe: boolean;
  readonly tioEnabled: boolean;
}

/** The SEV-SNP policy block (JSON snake_case on the wire). */
export interface SevSnpPolicy {
  /** uint8. */
  readonly minimumBuild?: number;
  readonly minimumApiVersion: string;
  readonly minimumAbiVersion: string;
  /** uint32. */
  readonly minimumGuestSvn?: number;
  readonly minimumTcb: Tcb;
  readonly minimumLaunchTcb: Tcb;
  readonly guestPolicy: GuestPolicy;
  readonly platformInfo: SnpPlatform;
  readonly permitProvisionalFirmware: boolean;
  /** int64. */
  readonly vmpl?: bigint;
  readonly hostData: string;
  readonly imageId: string;
  readonly familyId: string;
  readonly requireAuthorKey: boolean;
  readonly requireIdBlock: boolean;
  /** uint64, kept exact. */
  readonly minimumLaunchMitigationVector?: bigint;
  readonly minimumCurrentMitigationVector?: bigint;
}

const MEMBERS = [
  "minimum_build",
  "minimum_api_version",
  "minimum_abi_version",
  "minimum_guest_svn",
  "minimum_tcb",
  "minimum_launch_tcb",
  "guest_policy",
  "platform_info",
  "permit_provisional_firmware",
  "vmpl",
  "host_data",
  "image_id",
  "family_id",
  "require_author_key",
  "require_id_block",
  "minimum_launch_mitigation_vector",
  "minimum_current_mitigation_vector",
] as const;
const TCB_MEMBERS = ["fmc_spl", "bl_spl", "tee_spl", "snp_spl", "ucode_spl"] as const;
const GUEST_POLICY_MEMBERS = [
  "debug",
  "smt",
  "migrate_ma",
  "single_socket",
  "cxl_allowed",
  "mem_aes256_xts",
  "rapl_dis",
  "ciphertext_hiding_dram",
  "page_swap_disable",
] as const;
const PLATFORM_INFO_MEMBERS = [
  "smt_enabled",
  "tsme_enabled",
  "ecc_enabled",
  "rapl_disabled",
  "ciphertext_hiding_dram",
  "alias_check_complete",
  "iommu_write_safe",
  "tio_enabled",
] as const;

const u8 = (o: JsonObject, key: string): number | undefined => {
  const v = uint(o, key, 8);
  return v === undefined ? undefined : Number(v);
};

function decodeTcb(o: JsonObject): Tcb {
  return {
    fmcSpl: u8(o, "fmc_spl"),
    blSpl: u8(o, "bl_spl"),
    teeSpl: u8(o, "tee_spl"),
    snpSpl: u8(o, "snp_spl"),
    ucodeSpl: u8(o, "ucode_spl"),
  };
}

/** Strict decode of the sev_snp block. */
export function decodeSevSnpPolicy(v: JsonValue, what: string): SevSnpPolicy {
  const o = object(v, what, MEMBERS);
  const g = struct(o, "guest_policy", GUEST_POLICY_MEMBERS);
  const pi = struct(o, "platform_info", PLATFORM_INFO_MEMBERS);
  const guestSvn = uint(o, "minimum_guest_svn", 32);
  return {
    minimumBuild: u8(o, "minimum_build"),
    minimumApiVersion: str(o, "minimum_api_version"),
    minimumAbiVersion: str(o, "minimum_abi_version"),
    minimumGuestSvn: guestSvn === undefined ? undefined : Number(guestSvn),
    minimumTcb: decodeTcb(struct(o, "minimum_tcb", TCB_MEMBERS)),
    minimumLaunchTcb: decodeTcb(struct(o, "minimum_launch_tcb", TCB_MEMBERS)),
    guestPolicy: {
      debug: bool(g, "debug"),
      smt: bool(g, "smt"),
      migrateMa: bool(g, "migrate_ma"),
      singleSocket: bool(g, "single_socket"),
      cxlAllowed: bool(g, "cxl_allowed"),
      memAes256Xts: bool(g, "mem_aes256_xts"),
      raplDis: bool(g, "rapl_dis"),
      ciphertextHidingDram: bool(g, "ciphertext_hiding_dram"),
      pageSwapDisable: bool(g, "page_swap_disable"),
    },
    platformInfo: {
      smtEnabled: bool(pi, "smt_enabled"),
      tsmeEnabled: bool(pi, "tsme_enabled"),
      eccEnabled: bool(pi, "ecc_enabled"),
      raplDisabled: bool(pi, "rapl_disabled"),
      ciphertextHidingDram: bool(pi, "ciphertext_hiding_dram"),
      aliasCheckComplete: bool(pi, "alias_check_complete"),
      iommuWriteSafe: bool(pi, "iommu_write_safe"),
      tioEnabled: bool(pi, "tio_enabled"),
    },
    permitProvisionalFirmware: bool(o, "permit_provisional_firmware"),
    vmpl: int64(o, "vmpl"),
    hostData: str(o, "host_data"),
    imageId: str(o, "image_id"),
    familyId: str(o, "family_id"),
    requireAuthorKey: bool(o, "require_author_key"),
    requireIdBlock: bool(o, "require_id_block"),
    minimumLaunchMitigationVector: uint(o, "minimum_launch_mitigation_vector", 64),
    minimumCurrentMitigationVector: uint(o, "minimum_current_mitigation_vector", 64),
  };
}

/** Required fields present; vmpl 0..3; require_* rejected; TCBs; versions; hex lengths. */
export function validateSevSnpPolicy(p: SevSnpPolicy): void {
  if (p.minimumBuild === undefined) throw new Error("minimum_build is required");
  if (p.minimumApiVersion === "") throw new Error("minimum_api_version is required");
  if (p.minimumAbiVersion === "") throw new Error("minimum_abi_version is required");
  if (p.minimumGuestSvn === undefined) throw new Error("minimum_guest_svn is required");
  if (p.vmpl === undefined) throw new Error("vmpl is required");
  if (p.vmpl < 0n || p.vmpl > 3n) throw new Error("vmpl must be between 0 and 3");
  if (p.imageId === "") throw new Error("image_id is required");
  if (p.familyId === "") throw new Error("family_id is required");
  if (p.minimumLaunchMitigationVector === undefined) throw new Error("minimum_launch_mitigation_vector is required");
  if (p.minimumCurrentMitigationVector === undefined) throw new Error("minimum_current_mitigation_vector is required");
  if (p.requireAuthorKey || p.requireIdBlock) {
    throw new Error("require_author_key and require_id_block are not supported (no trusted key material is modeled)");
  }
  validateTcb("minimum_tcb", p.minimumTcb);
  validateTcb("minimum_launch_tcb", p.minimumLaunchTcb);
  validatePolicyVersion("minimum_api_version", p.minimumApiVersion);
  validatePolicyVersion("minimum_abi_version", p.minimumAbiVersion);
  if (p.hostData !== "") validatePolicyHex("host_data", p.hostData, 32);
  validatePolicyHex("image_id", p.imageId, 16);
  validatePolicyHex("family_id", p.familyId, 16);
}

function validateTcb(name: string, t: Tcb): void {
  const missing =
    t.blSpl === undefined ? "bl_spl" : t.teeSpl === undefined ? "tee_spl" : t.snpSpl === undefined ? "snp_spl" : t.ucodeSpl === undefined ? "ucode_spl" : undefined;
  if (missing !== undefined) throw new Error(`${name}: ${missing} is required`);
}

/** "maj.min", each a decimal uint8. */
export function validatePolicyVersion(name: string, version: string): void {
  const dot = version.indexOf(".");
  const major = dot < 0 ? version : version.slice(0, dot);
  const minor = dot < 0 ? "" : version.slice(dot + 1);
  if (dot < 0 || !decimalDigits(major) || !decimalDigits(minor)) {
    throw new Error(`${name} ${JSON.stringify(version)} is not maj.min`);
  }
  if (BigInt(major) > 255n) throw new Error(`${name} major: value out of range`);
  if (BigInt(minor) > 255n) throw new Error(`${name} minor: value out of range`);
}

function decimalDigits(value: string): boolean {
  return /^[0-9]+$/.test(value);
}
