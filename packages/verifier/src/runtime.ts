import { parseAllDocuments } from "yaml";
import {
  hex,
  object,
  parseJSON,
  sha256,
  string,
  text,
  unhex,
} from "./encoding.js";
import type { Reference } from "./references.js";
import { PLATFORM_REPO } from "./references.js";
import type { SNPMeasurement, TDXMeasurement } from "./types.js";
export const MAX_ARTIFACT_SIZE = 1 << 20;
export function fullVersion(value: unknown): string {
  const s = string(value);
  const m =
    /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(
      s,
    );
  if (!m || m[4]?.split(".").some((x) => /^0[0-9]+$/.test(x)))
    throw new Error("Full semantic version required");
  return s;
}
export const canonicalVersion = (v: string): string =>
  fullVersion(v).split("+")[0];
export function runtimePin(bytes: Uint8Array): Reference {
  if (!bytes.length || bytes.length > MAX_ARTIFACT_SIZE)
    throw new Error("Config size outside bounds");
  const docs = parseAllDocuments(text(bytes), { uniqueKeys: true });
  if (docs.length !== 1 || docs[0].errors.length)
    throw new Error("Config must contain one valid YAML document");
  const config = object(docs[0].toJS({ maxAliasCount: 100 }));
  const value = string(config["cvm-version"]);
  const parts = value.split("@sha256:");
  if (parts.length !== 2)
    throw new Error("cvm-version must pin a SHA-256 runtime manifest");
  const tag = fullVersion("v" + parts[0].replace(/^v/, ""));
  unhex(parts[1], 32);
  return { repo: PLATFORM_REPO, tag, digest: parts[1] };
}
export interface RuntimeManifest {
  version: string;
  snp: SNPMeasurement;
  tdx: TDXMeasurement;
}
export function decodeRuntimeManifest(bytes: Uint8Array): RuntimeManifest {
  if (!bytes.length || bytes.length > MAX_ARTIFACT_SIZE)
    throw new Error("Runtime manifest size outside bounds");
  const m = object(parseJSON(bytes));
  const version = fullVersion(m.version),
    igvm = object(m.igvm);
  if (igvm.format_version !== 1) throw new Error("Unsupported runtime format");
  const snp = object(igvm.snp_launch),
    tdx = object(igvm.tdx_launch);
  unhex(snp.measurement, 48);
  unhex(tdx.mrtd, 48);
  for (const name of ["rtmr0", "rtmr1", "rtmr2", "rtmr3"])
    if (tdx[name] !== "0".repeat(96))
      throw new Error("Runtime v1 requires zero TDX RTMRs");
  return {
    version,
    snp: { type: "sev-snp", launch: snp.measurement },
    tdx: {
      type: "tdx",
      mrtd: tdx.mrtd,
      rtmr0: tdx.rtmr0,
      rtmr1: tdx.rtmr1,
      rtmr2: tdx.rtmr2,
      rtmr3: tdx.rtmr3,
    },
  };
}
export async function parseRuntimeManifest(
  bytes: Uint8Array,
  pin: Reference,
): Promise<RuntimeManifest> {
  const m = decodeRuntimeManifest(bytes);
  if (hex(await sha256(bytes)) !== pin.digest)
    throw new Error("Runtime manifest digest does not match config pin");
  if (m.version !== pin.tag)
    throw new Error("Runtime manifest version does not match config pin");
  return m;
}
