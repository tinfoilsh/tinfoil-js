/** Shared steps of policy assembly: the machine's policy, the caller's pins, and the completeness rule. */
import { registerHex, type Expected, type Measurement, type Register } from "../../measurement.js";
import { PLATFORM_SEV_SNP, PLATFORM_TDX, policyFor, type Artifact, type Platform, type Policy } from "../policy/artifact.js";

/** The authenticated identity and platform a policy is looked up for. */
export interface Machine {
  readonly platform: Platform;
  readonly identity: string;
}

/** Looks up the machine's policy in the endorsements artifact for the quote's platform and identity. */
export function resolvePolicy(endorsements: Artifact, q: Machine): { policy: Policy; policyName: string } {
  const { name, policy } = policyFor(endorsements, q.identity, q.platform);
  return { policy, policyName: name };
}

/**
 * Fills the registers the code leaves open from `pins`, and requires every
 * pin the code also fixes to agree with it. `code` is for the enclave's
 * platform; pins for the other platform reject.
 */
export function applyPins(code: Expected, platform: Platform, pins: Expected | undefined): Expected {
  if (pins === undefined) return code;
  let conflict: string | undefined;
  const fill = (name: string, fixed: Register | undefined, pin: Register | undefined): Register | undefined => {
    if (pin === undefined) return fixed;
    if (fixed === undefined) return pin;
    if (registerHex(fixed) !== registerHex(pin) && conflict === undefined) {
      conflict = `pinned ${name} does not match the signed release measurement`;
    }
    return fixed;
  };
  let merged: Expected;
  switch (pins.platform) {
    case PLATFORM_SEV_SNP:
      if (code.platform !== PLATFORM_SEV_SNP) {
        throw new Error(`pinned registers are for ${PLATFORM_SEV_SNP}, but the enclave is ${platform}`);
      }
      merged = { platform: PLATFORM_SEV_SNP, launch: fill("launch measurement", code.launch, pins.launch) };
      break;
    case PLATFORM_TDX:
      if (code.platform !== PLATFORM_TDX) {
        throw new Error(`pinned registers are for ${PLATFORM_TDX}, but the enclave is ${platform}`);
      }
      merged = {
        platform: PLATFORM_TDX,
        mrtd: fill("MRTD", code.mrtd, pins.mrtd),
        rtmr0: fill("RTMR0", code.rtmr0, pins.rtmr0),
        rtmr1: fill("RTMR1", code.rtmr1, pins.rtmr1),
        rtmr2: fill("RTMR2", code.rtmr2, pins.rtmr2),
        rtmr3: fill("RTMR3", code.rtmr3, pins.rtmr3),
      };
      break;
    default:
      throw new Error("unsupported pinned measurement");
  }
  if (conflict !== undefined) throw new Error(conflict);
  return merged;
}

/** The measurement `e` requires; a register left unconstrained rejects, so assembly never leaves one unchecked. */
export function complete(e: Expected): Measurement {
  const missing: string[] = [];
  const get = (name: string, r: Register | undefined): Register => {
    if (r === undefined) {
      missing.push(name);
      return new Uint8Array(48);
    }
    return r;
  };
  let m: Measurement;
  switch (e.platform) {
    case PLATFORM_SEV_SNP:
      m = { platform: PLATFORM_SEV_SNP, launch: get("launch measurement", e.launch) };
      break;
    case PLATFORM_TDX:
      m = {
        platform: PLATFORM_TDX,
        mrtd: get("MRTD", e.mrtd),
        rtmr0: get("RTMR0", e.rtmr0),
        rtmr1: get("RTMR1", e.rtmr1),
        rtmr2: get("RTMR2", e.rtmr2),
        rtmr3: get("RTMR3", e.rtmr3),
      };
      break;
    default:
      throw new Error("unsupported expected measurement");
  }
  if (missing.length > 0) throw new Error(`nothing fixes the expected ${missing.join(", ")}`);
  return m;
}
