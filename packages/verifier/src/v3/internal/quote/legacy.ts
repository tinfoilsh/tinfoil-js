/** Reference values for a code release: the platform policy and the registers the release fixes. */
import { notImplemented } from "../../errors.js";
import type { Expected, ExpectedSevSnp, ExpectedTdx } from "../../measurement.js";
import type { Artifact } from "../policy/artifact.js";
import type { Shape } from "../policy/shape.js";
import type { Authenticated, ResolvedValues } from "./quote.js";

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
  return notImplemented("quote.resolveLegacy");
}
