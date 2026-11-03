/** The IGVM runtime manifest pinned by a config. Mirrors tinfoil-go verify/internal/runtime/manifest.go. */
import type { RuntimeReference } from "../../document/collateral/runtime.js";
import { sha256, toHex } from "../bytes.js";
import { decodeLowerHex } from "../canonical.js";
import { int64, object, str } from "../json/decode.js";
import { strictParse, type JsonObject } from "../json/index.js";
import * as semver from "../semver.js";

export const FORMAT_VERSION = 1;
export const MEASUREMENT_SIZE = 48;
export const MAX_MANIFEST_SIZE = 1 << 20;

export interface TdxLaunch {
  readonly mrtd: string;
  readonly rtmr0: string;
  readonly rtmr1: string;
  readonly rtmr2: string;
  readonly rtmr3: string;
}

export interface Measurements {
  readonly formatVersion: bigint;
  readonly snpLaunch?: { readonly measurement: string };
  readonly tdxLaunch?: TdxLaunch;
}

export interface Manifest {
  readonly version: string;
  /** The "igvm" member; undefined for an old manifest without it. */
  readonly measurements?: Measurements;
}

/** The TDX registers in order. */
export function tdxRegisters(t: TdxLaunch): [string, string, string, string, string] {
  return [t.mrtd, t.rtmr0, t.rtmr1, t.rtmr2, t.rtmr3];
}

/** The manifest's SHA-256 must equal the pin, then it decodes, then its version must equal the tag. */
export async function parseManifest(data: Uint8Array, expected: RuntimeReference): Promise<Manifest> {
  if (toHex(await sha256(data)) !== expected.digest) {
    throw new Error("runtime manifest does not match the config's digest pin");
  }
  const m = decodeManifest(data);
  if (m.version !== expected.tag) {
    throw new Error(`runtime manifest version ${JSON.stringify(m.version)} does not match the config's pin ${JSON.stringify(expected.tag)}`);
  }
  return m;
}

/**
 * Size limit, full semver, format_version 1, both launches, 48-byte lowercase
 * hex, zero RTMRs. Unknown members are allowed here, as in Go (no
 * RejectUnknownMembers); duplicate names still reject.
 */
export function decodeManifest(data: Uint8Array): Manifest {
  if (data.length === 0 || data.length > MAX_MANIFEST_SIZE) {
    throw new Error("runtime manifest size is outside allowed bounds");
  }
  let m: Manifest;
  try {
    const o = object(strictParse(data), "runtime manifest");
    const igvm = optObject(o, "igvm");
    m = {
      version: str(o, "version"),
      measurements: igvm && {
        formatVersion: int64(igvm, "format_version") ?? 0n,
        snpLaunch: mapOpt(optObject(igvm, "snp_launch"), (s) => ({ measurement: str(s, "measurement") })),
        tdxLaunch: mapOpt(optObject(igvm, "tdx_launch"), (t) => ({
          mrtd: str(t, "mrtd"),
          rtmr0: str(t, "rtmr0"),
          rtmr1: str(t, "rtmr1"),
          rtmr2: str(t, "rtmr2"),
          rtmr3: str(t, "rtmr3"),
        })),
      },
    };
  } catch (err) {
    throw new Error(`parsing runtime manifest: ${(err as Error).message}`);
  }
  if (!semver.isValid(m.version) || semver.canonical(m.version) + semver.build(m.version) !== m.version) {
    throw new Error("runtime manifest version must be a full semantic version");
  }
  if (m.measurements === undefined || m.measurements.formatVersion !== BigInt(FORMAT_VERSION)) {
    throw new Error("runtime manifest format is unsupported");
  }
  const g = m.measurements;
  if (g.snpLaunch === undefined || g.tdxLaunch === undefined) {
    throw new Error("runtime manifest requires complete launch measurements");
  }
  decodeLowerHex("SNP measurement", g.snpLaunch.measurement, MEASUREMENT_SIZE);
  decodeLowerHex("MRTD", g.tdxLaunch.mrtd, MEASUREMENT_SIZE);
  const zero = "0".repeat(MEASUREMENT_SIZE * 2);
  for (const value of tdxRegisters(g.tdxLaunch).slice(1)) {
    if (value !== zero) throw new Error("runtime format v1 requires zero TDX RTMRs");
  }
  return m;
}

/** A Go pointer-to-struct member decoded without RejectUnknownMembers: absent or null is undefined; unknown members are ignored. */
function optObject(o: JsonObject, key: string): JsonObject | undefined {
  const v = o.get(key);
  return v === undefined || v === null ? undefined : object(v, key);
}

function mapOpt<T, U>(v: T | undefined, f: (v: T) => U): U | undefined {
  return v === undefined ? undefined : f(v);
}
