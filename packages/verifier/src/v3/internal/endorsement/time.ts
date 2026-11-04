/** The acceptance window for an approval time. */

export const DEFAULT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_FUTURE_SKEW_MS = 5 * 60 * 1000;

export interface TimePolicy {
  readonly earliest: Date;
  readonly latest: Date;
}

/** [now - maxAge, now + futureSkew]; zero selects the default, negative or non-finite rejects, `now` is required. */
export function newTimePolicy(now: Date, maxAgeMs: number, futureSkewMs: number): TimePolicy {
  if (!Number.isFinite(now.getTime())) throw new Error("appraisal time is required");
  if (!(maxAgeMs >= 0) || !(futureSkewMs >= 0)) throw new Error("time policy bounds must be non-negative numbers");
  const maxAge = maxAgeMs === 0 ? DEFAULT_MAX_AGE_MS : maxAgeMs;
  const skew = futureSkewMs === 0 ? DEFAULT_FUTURE_SKEW_MS : futureSkewMs;
  return { earliest: new Date(now.getTime() - maxAge), latest: new Date(now.getTime() + skew) };
}

/** Rejects an invalid time, an invalid window, and a time outside [earliest, latest]. */
export function checkTime(policy: TimePolicy, at: Date): void {
  const t = at.getTime();
  const earliest = policy.earliest.getTime();
  const latest = policy.latest.getTime();
  if (!Number.isFinite(t)) throw new Error("time is invalid");
  if (!Number.isFinite(earliest) || !Number.isFinite(latest)) throw new Error("time window is invalid");
  if (t < earliest || t > latest) throw new Error(`time ${at.toISOString()} is outside the accepted window`);
}
