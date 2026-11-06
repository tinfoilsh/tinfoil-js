/** Reference values for a config-pinned runtime: the platform policy and the runtime's launch measurements. */
import { parseRegister, type Expected, type Register } from "../../measurement.js";
import { PLATFORM_SEV_SNP, PLATFORM_TDX, type Artifact } from "../policy/artifact.js";
import { tdxRegisters, type Measurements } from "../runtime/manifest.js";
import type { Authenticated, ResolvedValues } from "./quote.js";
import { applyPins, resolvePolicy } from "./resolve.js";

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
  if (r.runtime.snpLaunch === undefined || r.runtime.tdxLaunch === undefined) {
    throw new Error("complete runtime endorsements are required");
  }
  if (r.hash.length !== 32) throw new Error("config hash must be 32 bytes");
  const { policy, policyName } = resolvePolicy(r.endorsements, q);
  let code: Expected;
  let hostData = new Uint8Array(32);
  const configId = new Uint8Array(48);
  switch (q.platform) {
    case PLATFORM_SEV_SNP: {
      if (policy.sevSnp!.hostData !== "") throw new Error("config runtime cannot be combined with platform host_data");
      hostData = r.hash.slice();
      code = { platform: PLATFORM_SEV_SNP, launch: register("runtime SNP launch measurement", r.runtime.snpLaunch.measurement) };
      break;
    }
    case PLATFORM_TDX: {
      if ((policy.tdx!.platformMeasurements ?? []).length !== 0) {
        throw new Error("config runtime cannot be combined with platform_measurements");
      }
      configId.set(r.hash);
      const [mrtd, rtmr0, rtmr1, rtmr2, rtmr3] = tdxRegisters(r.runtime.tdxLaunch).map((value, i) => register(`runtime TDX register ${i}`, value));
      code = { platform: PLATFORM_TDX, mrtd, rtmr0, rtmr1, rtmr2, rtmr3 };
      break;
    }
    default:
      throw new Error(`unsupported platform ${JSON.stringify(q.platform)}`);
  }
  const expected = applyPins(code, q.platform, pins);
  return { policy, policyName, platformMeasurementName: "", code, expected, hostData, configId };
}

function register(label: string, hex: string): Register {
  try {
    return parseRegister(hex);
  } catch (err) {
    throw new Error(`${label}: ${(err as Error).message}`);
  }
}
