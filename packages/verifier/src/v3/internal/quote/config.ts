/** Reference values for a config-pinned runtime: the platform policy and the runtime's launch measurements. */
import { notImplemented } from "../../errors.js";
import type { Expected } from "../../measurement.js";
import type { Artifact } from "../policy/artifact.js";
import type { Measurements } from "../runtime/manifest.js";
import type { Authenticated, ResolvedValues } from "./quote.js";

export interface ConfigReferenceValues {
  readonly kind: "config";
  readonly endorsements: Artifact;
  readonly runtime: Measurements;
  /** SHA-256 of the config bytes: the expected HOST_DATA (SEV-SNP) or MRCONFIGID (TDX). */
  readonly hash: Uint8Array;
}

/**
 * SEV-SNP: the policy must declare no host_data, and the launch measurement
 * comes from the manifest. TDX: the policy must declare no platform
 * measurements, MRCONFIGID is the config hash, and all five registers come
 * from the manifest. Then pins apply.
 */
export function resolveConfig(r: ConfigReferenceValues, q: Authenticated, pins: Expected | undefined): ResolvedValues {
  return notImplemented("quote.resolveConfig");
}
