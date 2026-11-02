/** Predicate type of the platform-endorsements artifact. */
export const ARTIFACT_FORMAT = "https://tinfoil.sh/predicate/platform-endorsements/v1";

export const PLATFORM_SEV_SNP = "sev-snp";
export const PLATFORM_TDX = "tdx";
export type Platform = typeof PLATFORM_SEV_SNP | typeof PLATFORM_TDX;
