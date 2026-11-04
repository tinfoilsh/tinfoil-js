/** The acceptance window for an approval time. */

export const DEFAULT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_FUTURE_SKEW_MS = 5 * 60 * 1000;

export interface TimePolicy {
  readonly earliest: Date;
  readonly latest: Date;
}

/** [now - maxAge, now + futureSkew]; zero selects the default, negative rejects, `now` is required. */
export function newTimePolicy(now: Date, maxAgeMs: number, futureSkewMs: number): TimePolicy {
  if (Number.isNaN(now.getTime())) throw new Error("appraisal time is required");
  if (maxAgeMs < 0 || futureSkewMs < 0) throw new Error("time policy bounds must not be negative");
  const maxAge = maxAgeMs === 0 ? DEFAULT_MAX_AGE_MS : maxAgeMs;
  const skew = futureSkewMs === 0 ? DEFAULT_FUTURE_SKEW_MS : futureSkewMs;
  return { earliest: new Date(now.getTime() - maxAge), latest: new Date(now.getTime() + skew) };
}

/** Rejects a time outside [earliest, latest]. */
export function checkTime(policy: TimePolicy, at: Date): void {
  if (at.getTime() < policy.earliest.getTime() || at.getTime() > policy.latest.getTime()) {
    throw new Error(`time ${at.toISOString()} is outside the accepted window`);
  }
}
