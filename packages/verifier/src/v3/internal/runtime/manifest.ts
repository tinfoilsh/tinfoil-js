/** The IGVM runtime manifest pinned by a config. Mirrors tinfoil-go verify/internal/runtime/manifest.go. */
import type { RuntimeReference } from "../../document/collateral/runtime.js";
import { notImplemented } from "../../errors.js";

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
  readonly formatVersion: number;
  readonly snpLaunch: { readonly measurement: string };
  readonly tdxLaunch: TdxLaunch;
}

export interface Manifest {
  readonly version: string;
  readonly measurements: Measurements;
}

/** The manifest's SHA-256 must equal the pin, then it decodes, then its version must equal the tag. */
export async function parseManifest(data: Uint8Array, expected: RuntimeReference): Promise<Manifest> {
  return notImplemented("runtime.parseManifest");
}

/**
 * Size limit, full semver, format_version 1, both launches, 48-byte lowercase
 * hex. Unknown members are allowed here, as in Go.
 */
export function decodeManifest(data: Uint8Array): Manifest {
  return notImplemented("runtime.decodeManifest");
}
