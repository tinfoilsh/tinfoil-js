// Measurement value types shared by code provenance and quote verification
// (Go: verifier/measurement). Display helpers (Fingerprint, String) are not
// part of the v3 verification flow and are not ported.

export const RTMR3_ZERO =
  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

export type PredicateType = string;

// CC guest v2 types include the TLS key fingerprint and optionally HPKE public key
export const SevGuestV2: PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
export const TdxGuestV2: PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v2";

export const SnpTdxMultiPlatformV1: PredicateType = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";

export interface Measurement {
  type: PredicateType;
  registers: string[];
}

// HardwareMeasurement represents the measurement values for a single
// platform from the hardware measurement repo.
export interface HardwareMeasurement {
  id: string; // platform@digest
  mrtd: string;
  rtmr0: string;
}
