import { describe, expect, it } from "vitest";
import {
  checkTime,
  DEFAULT_FUTURE_SKEW_MS,
  DEFAULT_MAX_AGE_MS,
  newTimePolicy,
} from "../src/internal/endorsement/time.js";

const now = new Date("2026-01-01T00:00:00Z");

describe("newTimePolicy", () => {
  it("builds [now - maxAge, now + skew] with defaults for zero", () => {
    const p = newTimePolicy(now, 0, 0);
    expect(p.earliest).toEqual(new Date(now.getTime() - DEFAULT_MAX_AGE_MS));
    expect(p.latest).toEqual(new Date(now.getTime() + DEFAULT_FUTURE_SKEW_MS));
    const q = newTimePolicy(now, 1000, 10);
    expect(q.earliest).toEqual(new Date(now.getTime() - 1000));
    expect(q.latest).toEqual(new Date(now.getTime() + 10));
  });

  it("requires a valid clock and non-negative finite bounds", () => {
    expect(() => newTimePolicy(new Date(NaN), 0, 0)).toThrow(/appraisal time is required/);
    expect(() => newTimePolicy(now, -1, 0)).toThrow(/non-negative/);
    expect(() => newTimePolicy(now, 0, -1)).toThrow(/non-negative/);
    expect(() => newTimePolicy(now, NaN, 0)).toThrow(/non-negative/);
  });
});

describe("checkTime", () => {
  const policy = newTimePolicy(now, 0, 0);

  it("accepts the window edges and rejects beyond them", () => {
    expect(() => checkTime(policy, policy.earliest)).not.toThrow();
    expect(() => checkTime(policy, policy.latest)).not.toThrow();
    expect(() => checkTime(policy, new Date(policy.earliest.getTime() - 1))).toThrow(/outside the accepted window/);
    expect(() => checkTime(policy, new Date(policy.latest.getTime() + 1))).toThrow(/outside the accepted window/);
  });

  it("rejects an invalid time and an invalid window instead of comparing them", () => {
    expect(() => checkTime(policy, new Date(NaN))).toThrow(/time is invalid/);
    expect(() => checkTime({ earliest: new Date(NaN), latest: policy.latest }, now)).toThrow(/window is invalid/);
    expect(() => checkTime({ earliest: policy.earliest, latest: new Date(NaN) }, now)).toThrow(/window is invalid/);
  });
});
