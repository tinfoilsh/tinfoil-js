/**
 * The platform-endorsements artifact: per-machine policies and, in v1, TDX
 * platform measurements. Parsed fail-closed. Mirrors tinfoil-go
 * verify/internal/policy/artifact.go.
 */
import { map, object, optStruct, str } from "../../internal/json/decode.js";
import { strictParse, type JsonValue } from "../../internal/json/index.js";
import { decodeSevSnpPolicy, validateSevSnpPolicy, type SevSnpPolicy } from "./sev.js";
import { decodeShape, decodeStack, formatShape, satisfies, SHAPE_MEMBERS, type Shape, type Stack } from "./shape.js";
import { decodeTdxPolicy, validatePolicyHex, validateTdxPolicy, type TdxPolicy } from "./tdx.js";

/** Predicate type of the platform-endorsements artifact. */
export const ARTIFACT_FORMAT = "https://tinfoil.sh/predicate/platform-endorsements/v1";
export const ARTIFACT_FORMAT_V2 = "https://tinfoil.sh/predicate/platform-endorsements/v2";

export const PLATFORM_SEV_SNP = "sev-snp";
export const PLATFORM_TDX = "tdx";
export type Platform = typeof PLATFORM_SEV_SNP | typeof PLATFORM_TDX;

const SEV_IDENTIFIER_HEX_LEN = 128;
const TDX_IDENTIFIER_HEX_LEN = 32;
const LOWER_HEX_RE = /^[0-9a-f]+$/;

/** TDX platform registers for one VM shape. */
export interface PlatformMeasurement {
  readonly mrtd: string;
  readonly rtmr0: string;
  readonly shape?: Shape;
  readonly stack?: Stack;
}

/** A named policy. `platform` is as sent; validation requires it to name exactly one block. */
export interface Policy {
  readonly platform: string;
  readonly sevSnp?: SevSnpPolicy;
  readonly tdx?: TdxPolicy;
}

export interface Artifact {
  readonly format: string;
  /** Empty in v2. */
  readonly measurements: ReadonlyMap<string, PlatformMeasurement>;
  /** Machine identifier (lowercase hex) → policy name. */
  readonly machines: ReadonlyMap<string, string>;
  readonly policies: ReadonlyMap<string, Policy>;
}

/** Strict decode, format v1 or v2, then structural validation. */
export function parse(data: Uint8Array): Artifact {
  let a: Artifact;
  try {
    a = decodeArtifact(strictParse(data));
  } catch (err) {
    throw new Error(`parsing policy artifact: ${(err as Error).message}`);
  }
  if (a.format !== ARTIFACT_FORMAT && a.format !== ARTIFACT_FORMAT_V2) {
    throw new Error(`unsupported artifact format ${JSON.stringify(a.format)}`);
  }
  validate(a);
  return a;
}

function decodeArtifact(v: JsonValue): Artifact {
  const o = object(v, "policy artifact", ["format", "measurements", "machines", "policies"]);
  return {
    format: str(o, "format"),
    measurements: map(o, "measurements", (m, name) => {
      const mo = object(m, `measurement ${JSON.stringify(name)}`, ["mrtd", "rtmr0", "shape", "stack"]);
      const shape = optStruct(mo, "shape", SHAPE_MEMBERS);
      const stack = mo.get("stack");
      return {
        mrtd: str(mo, "mrtd"),
        rtmr0: str(mo, "rtmr0"),
        shape: shape && decodeShape(shape),
        stack: stack === undefined || stack === null ? undefined : decodeStack(stack, "stack"),
      };
    }),
    machines: map(o, "machines", (p, name) => {
      if (p === null) return "";
      if (typeof p !== "string") throw new Error(`machine ${JSON.stringify(name)} policy name must be a string`);
      return p;
    }),
    policies: map(o, "policies", (p, name) => {
      const po = object(p, `policy ${JSON.stringify(name)}`, ["platform", "sev_snp", "tdx"]);
      const sev = po.get("sev_snp");
      const tdx = po.get("tdx");
      return {
        platform: str(po, "platform"),
        sevSnp: sev === undefined || sev === null ? undefined : decodeSevSnpPolicy(sev, "sev_snp"),
        tdx: tdx === undefined || tdx === null ? undefined : decodeTdxPolicy(tdx, "tdx"),
      };
    }),
  };
}

function validate(a: Artifact): void {
  if (a.format === ARTIFACT_FORMAT_V2 && a.measurements.size !== 0) {
    throw new Error("platform endorsement v2 excludes workload measurements");
  }
  for (const [name, p] of a.policies) {
    const q = JSON.stringify(name);
    switch (p.platform) {
      case PLATFORM_SEV_SNP: {
        if (p.sevSnp === undefined || p.tdx !== undefined) {
          throw new Error(`policy ${q}: platform sev-snp requires exactly the sev_snp block`);
        }
        if ((a.format === ARTIFACT_FORMAT) !== (p.sevSnp.hostData !== "")) {
          throw new Error(`policy ${q}: host_data is required in v1 and excluded in v2`);
        }
        withPrefix(`policy ${q}`, () => validateSevSnpPolicy(p.sevSnp!));
        break;
      }
      case PLATFORM_TDX: {
        if (p.tdx === undefined || p.sevSnp !== undefined) {
          throw new Error(`policy ${q}: platform tdx requires exactly the tdx block`);
        }
        const refs = p.tdx.platformMeasurements ?? [];
        if ((a.format === ARTIFACT_FORMAT) !== (refs.length !== 0)) {
          throw new Error(`policy ${q}: platform_measurements are required in v1 and excluded in v2`);
        }
        withPrefix(`policy ${q}`, () => validateTdxPolicy(p.tdx!));
        for (const ref of refs) {
          if (!a.measurements.has(ref)) {
            throw new Error(`policy ${q}: platform_measurements ref ${JSON.stringify(ref)} not in measurements`);
          }
        }
        break;
      }
      default:
        throw new Error(`policy ${q}: unsupported platform ${JSON.stringify(p.platform)}`);
    }
  }

  for (const [name, m] of a.measurements) {
    const q = JSON.stringify(name);
    if (m.shape === undefined) throw new Error(`measurement ${q}: shape is required`);
    if (m.shape.cpus <= 0n || m.shape.memoryMb <= 0n || m.shape.disks <= 0n) {
      throw new Error(`measurement ${q}: cpus, memory_mb, and disks must be positive`);
    }
    if (m.shape.gpus !== undefined && m.shape.gpus < 0n) throw new Error(`measurement ${q}: gpus must be non-negative`);
    withPrefix(`measurement ${q}`, () => validatePolicyHex("mrtd", m.mrtd, 48));
    withPrefix(`measurement ${q}`, () => validatePolicyHex("rtmr0", m.rtmr0, 48));
  }

  for (const [identifier, policyName] of a.machines) {
    const p = a.policies.get(policyName);
    const id = truncId(identifier);
    if (p === undefined) throw new Error(`machine ${id}...: unknown policy ${JSON.stringify(policyName)}`);
    if (!LOWER_HEX_RE.test(identifier)) throw new Error(`machine ${id}...: identifier is not lowercase hex`);
    switch (p.platform) {
      case PLATFORM_SEV_SNP:
        if (identifier.length !== SEV_IDENTIFIER_HEX_LEN) {
          throw new Error(`machine ${id}...: sev-snp identifier must be ${SEV_IDENTIFIER_HEX_LEN} hex chars, got ${identifier.length}`);
        }
        break;
      case PLATFORM_TDX:
        if (identifier.length !== TDX_IDENTIFIER_HEX_LEN) {
          throw new Error(`machine ${id}...: tdx identifier must be ${TDX_IDENTIFIER_HEX_LEN} hex chars, got ${identifier.length}`);
        }
        break;
    }
  }
}

function withPrefix(prefix: string, f: () => void): void {
  try {
    f();
  } catch (err) {
    throw new Error(`${prefix}: ${(err as Error).message}`);
  }
}

/** The policy for a machine on `platform`, and its name. */
export function policyFor(a: Artifact, identifierHex: string, platform: Platform): { name: string; policy: Policy } {
  const name = a.machines.get(identifierHex);
  if (name === undefined) throw new Error(`platform identifier ${truncId(identifierHex)}... is not endorsed`);
  const policy = a.policies.get(name)!;
  if (policy.platform !== platform) {
    throw new Error(`policy ${JSON.stringify(name)} is for platform ${JSON.stringify(policy.platform)}, evidence is ${JSON.stringify(platform)}`);
  }
  return { name, policy };
}

/** Hex of an exact byte length, either case (Go policy.DecodeHex). */
export function decodeHex(name: string, value: string, wantLen: number): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) throw new Error(`${name} is not hex`);
  if (value.length / 2 !== wantLen) throw new Error(`${name} must be ${wantLen} bytes, got ${value.length / 2}`);
  const out = new Uint8Array(wantLen);
  for (let i = 0; i < wantLen; i++) out[i] = parseInt(value.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function truncId(id: string): string {
  return id.length > 16 ? id.slice(0, 16) : id;
}

/** The first shape-satisfying platform measurement whose MRTD and RTMR0 equal the quote's. */
export function resolvePlatformMeasurement(
  a: Artifact,
  p: TdxPolicy,
  required: Shape | undefined,
  mrtdHex: string,
  rtmr0Hex: string,
): { name: string; measurement: PlatformMeasurement } {
  if (required === undefined) throw new Error("required VM shape is missing");
  let anyShapeMatch = false;
  for (const ref of p.platformMeasurements ?? []) {
    // Go reads a.Measurements[ref], the zero value for a missing name.
    const m: PlatformMeasurement = a.measurements.get(ref) ?? { mrtd: "", rtmr0: "" };
    if (!satisfies(m.shape, required)) continue;
    anyShapeMatch = true;
    if (m.mrtd === mrtdHex && m.rtmr0 === rtmr0Hex) return { name: ref, measurement: m };
  }
  if (!anyShapeMatch) {
    throw new Error(`no endorsed platform measurement matches the required VM shape ${formatShape(required)}`);
  }
  throw new Error(`platform measurements (mrtd ${truncId(mrtdHex)}...) do not match any allowed configuration`);
}
