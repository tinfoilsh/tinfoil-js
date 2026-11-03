import { notImplemented } from "../../errors.js";

/** AMD security patch levels. FMC is Turin-only. */
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
  readonly minimumBuild?: number;
  readonly minimumApiVersion: string;
  readonly minimumAbiVersion: string;
  readonly minimumGuestSvn?: number;
  readonly minimumTcb: Tcb;
  readonly minimumLaunchTcb: Tcb;
  readonly guestPolicy: GuestPolicy;
  readonly platformInfo: SnpPlatform;
  readonly permitProvisionalFirmware: boolean;
  readonly vmpl?: number;
  readonly hostData: string;
  readonly imageId: string;
  readonly familyId: string;
  readonly requireAuthorKey: boolean;
  readonly requireIdBlock: boolean;
  /** u64 on the wire. */
  readonly minimumLaunchMitigationVector?: bigint;
  readonly minimumCurrentMitigationVector?: bigint;
}

/** Strict decode of the sev_snp block. */
export function decodeSevSnpPolicy(v: unknown): SevSnpPolicy {
  return notImplemented("policy.decodeSevSnpPolicy");
}

/** Required fields present; vmpl 0..3; require_* rejected; TCBs; versions; hex lengths. */
export function validateSevSnpPolicy(p: SevSnpPolicy): void {
  return notImplemented("policy.validateSevSnpPolicy");
}
