/**
 * The platform-endorsements artifact: per-machine policies and, in v1, TDX
 * platform measurements. Parsed fail-closed. Mirrors tinfoil-go
 * verify/internal/policy/artifact.go.
 */
import { notImplemented } from "../../errors.js";
import type { SevSnpPolicy } from "./sev.js";
import type { Shape, Stack } from "./shape.js";
import type { TdxPolicy } from "./tdx.js";

/** Predicate type of the platform-endorsements artifact. */
export const ARTIFACT_FORMAT = "https://tinfoil.sh/predicate/platform-endorsements/v1";
export const ARTIFACT_FORMAT_V2 = "https://tinfoil.sh/predicate/platform-endorsements/v2";

export const PLATFORM_SEV_SNP = "sev-snp";
export const PLATFORM_TDX = "tdx";
export type Platform = typeof PLATFORM_SEV_SNP | typeof PLATFORM_TDX;

/** TDX platform registers for one VM shape. */
export interface PlatformMeasurement {
  readonly mrtd: string;
  readonly rtmr0: string;
  readonly shape?: Shape;
  readonly stack?: Stack;
}

/** A named policy; exactly one platform block is set. */
export interface Policy {
  readonly platform: Platform;
  readonly sevSnp?: SevSnpPolicy;
  readonly tdx?: TdxPolicy;
}

export interface Artifact {
  readonly format: string;
  /** v1 only. */
  readonly measurements?: ReadonlyMap<string, PlatformMeasurement>;
  /** Machine identifier (lowercase hex) → policy name. */
  readonly machines: ReadonlyMap<string, string>;
  readonly policies: ReadonlyMap<string, Policy>;
}

/** Strict decode, format v1 or v2, then structural validation. */
export function parse(data: Uint8Array): Artifact {
  return notImplemented("policy.parse");
}

/** The policy for a machine on `platform`, and its name. */
export function policyFor(a: Artifact, identifierHex: string, platform: Platform): { name: string; policy: Policy } {
  return notImplemented("policy.policyFor");
}

/** The first shape-satisfying platform measurement whose MRTD and RTMR0 equal the quote's. */
export function resolvePlatformMeasurement(
  a: Artifact,
  p: TdxPolicy,
  required: Shape | undefined,
  mrtdHex: string,
  rtmr0Hex: string,
): { name: string; measurement: PlatformMeasurement } {
  return notImplemented("policy.resolvePlatformMeasurement");
}

/** Hex of an exact byte length, either case (Go policy.DecodeHex). */
export function decodeHex(name: string, value: string, wantLen: number): Uint8Array {
  return notImplemented("policy.decodeHex");
}
