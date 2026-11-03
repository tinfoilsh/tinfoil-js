/** The acceptance window for an approval time. */
import { notImplemented } from "../../errors.js";

export const DEFAULT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_FUTURE_SKEW_MS = 5 * 60 * 1000;

export interface TimePolicy {
  readonly earliest: Date;
  readonly latest: Date;
}

/** [now - maxAge, now + futureSkew]; zero selects the default, negative rejects, `now` is required. */
export function newTimePolicy(now: Date, maxAgeMs: number, futureSkewMs: number): TimePolicy {
  return notImplemented("endorsement.newTimePolicy");
}

export function checkTime(policy: TimePolicy, at: Date): void {
  return notImplemented("endorsement.checkTime");
}
