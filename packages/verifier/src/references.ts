import { UsageError } from "./errors.js";
import { hex, unhex } from "./encoding.js";
export interface Reference {
  repo: string;
  tag: string;
  digest: string;
}
export function parseReference(value: string): Reference {
  if (typeof value !== "string")
    throw new UsageError("Trusted identity must be a string");
  const m =
    /^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:@([^@\s~^:?*\[\\]+))??(?:@sha256:([0-9a-f]{64}))?$/.exec(
      value,
    );
  if (!m)
    throw new UsageError(
      "Invalid trusted reference: expected owner/name[@tag][@sha256:digest]",
    );
  return { repo: m[1], tag: m[2] ?? "", digest: m[3] ?? "" };
}
/** @internal */
export const escapeRegExp = (v: string): string =>
  v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** @internal */
export function workflowIdentity(
  repo: string,
  workflow = "[^/@]+",
  ref = "refs/tags/[^@]+",
): RegExp {
  return new RegExp(
    "^https://github\\.com/" +
      escapeRegExp(repo) +
      "/\\.github/workflows/" +
      workflow +
      "@" +
      ref +
      "$",
  );
}
/** @internal */
export function register(v: unknown): string {
  return hex(unhex(v, 48, false));
}
/** @internal */
export const PLATFORM_REPO = "tinfoilsh/cvmimage";
/** @internal */
export const PLATFORM_V1 =
  "https://tinfoil.sh/predicate/platform-endorsements/v1";
/** @internal */
export const PLATFORM_V2 =
  "https://tinfoil.sh/predicate/platform-endorsements/v2";
/** @internal */
export const DEFAULT_MAX_AGE = 7 * 24 * 60 * 60 * 1000;
/** @internal */
export const MAX_FUTURE_SKEW = 5 * 60 * 1000;
/** @internal */
export function freshnessTime(at: Date, now: Date, maxAge: number): Date {
  if (
    !Number.isFinite(at.getTime()) ||
    at.getTime() > now.getTime() + MAX_FUTURE_SKEW
  )
    throw new Error("Approval timestamp is in the future");
  if (now.getTime() - at.getTime() > maxAge)
    throw new Error("Approval timestamp is stale");
  return at;
}
