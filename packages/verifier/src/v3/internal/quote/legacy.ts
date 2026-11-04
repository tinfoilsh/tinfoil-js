/** Reference values for a code release: the platform policy and the registers the release fixes. */
import { parseRegister, type Expected, type ExpectedSevSnp, type ExpectedTdx, type Register } from "../../measurement.js";
import { PLATFORM_SEV_SNP, PLATFORM_TDX, resolvePlatformMeasurement, type Artifact } from "../policy/artifact.js";
import { decodeHex } from "../policy/artifact.js";
import type { Shape } from "../policy/shape.js";
import type { Authenticated, ResolvedValues } from "./quote.js";
import { applyPins, resolvePolicy } from "./resolve.js";
import { platformMeasurements } from "./tdx/authenticate.js";

export interface LegacyReferenceValues {
  readonly kind: "legacy";
  readonly endorsements: Artifact;
  readonly sevSnp: ExpectedSevSnp;
  readonly tdx: ExpectedTdx;
  readonly shape?: Shape;
}

/**
 * The release's registers, then pins. SEV-SNP: HOST_DATA comes from the
 * policy. TDX: MRTD and RTMR0 come from the platform measurement whose shape
 * satisfies the release's, selected by the quote's own MRTD and RTMR0; RTMR3
 * defaults to zero.
 */
export function resolveLegacy(r: LegacyReferenceValues, q: Authenticated, pins: Expected | undefined): ResolvedValues {
  const { policy, policyName } = resolvePolicy(r.endorsements, q);
  let code: Expected;
  switch (q.platform) {
    case PLATFORM_SEV_SNP:
      code = r.sevSnp;
      break;
    case PLATFORM_TDX:
      code = r.tdx;
      break;
    default:
      throw new Error(`unsupported platform ${JSON.stringify(q.platform)}`);
  }
  const expected = applyPins(code, q.platform, pins);
  let hostData: Uint8Array = new Uint8Array(32);
  let configId = new Uint8Array(48);
  let platformMeasurementName = "";
  let completed = expected;
  if (q.platform === PLATFORM_SEV_SNP) {
    // The policy's host_data is validated as 32 lowercase hex bytes by the
    // artifact parser; an empty one (a v2 policy) cannot resolve a legacy
    // expectation and rejects here.
    hostData = decodeHex("host_data", policy.sevSnp!.hostData, 32);
  } else {
    // The release fixes only RTMR1 and RTMR2; the platform endorsements
    // supply MRTD and RTMR0, and an unpinned RTMR3 must be zero.
    const { mrtd, rtmr0 } = platformMeasurements(q.tdx!);
    const { name, measurement } = resolvePlatformMeasurement(r.endorsements, policy.tdx!, r.shape, mrtd, rtmr0);
    platformMeasurementName = name;
    const platformMrtd = register(`platform measurement ${JSON.stringify(name)} MRTD`, measurement.mrtd);
    const platformRtmr0 = register(`platform measurement ${JSON.stringify(name)} RTMR0`, measurement.rtmr0);
    if (expected.platform !== PLATFORM_TDX) throw new Error("expected a TDX measurement");
    completed = {
      platform: PLATFORM_TDX,
      mrtd: expected.mrtd ?? platformMrtd,
      rtmr0: expected.rtmr0 ?? platformRtmr0,
      rtmr1: expected.rtmr1,
      rtmr2: expected.rtmr2,
      rtmr3: expected.rtmr3 ?? new Uint8Array(48),
    };
    configId = new Uint8Array(48);
  }
  return { policy, policyName, platformMeasurementName, code, expected: completed, hostData, configId };
}

function register(label: string, hex: string): Register {
  try {
    return parseRegister(hex);
  } catch (err) {
    throw new Error(`${label}: ${(err as Error).message}`);
  }
}
