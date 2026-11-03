import { describe, expect, it } from "vitest";
import { build, canonical, isValid } from "../../src/v3/internal/semver.js";

// [version, isValid, canonical, build].
const cases: [string, boolean, string, string][] = [
  ["v1", true, "v1.0.0", ""],
  ["v1.2", true, "v1.2.0", ""],
  ["v1.2.3", true, "v1.2.3", ""],
  ["v0.0.0", true, "v0.0.0", ""],
  ["v1.2.3-pre", true, "v1.2.3-pre", ""],
  ["v1.2.3-pre+build", true, "v1.2.3-pre", "+build"],
  ["v1.2.3+build", true, "v1.2.3", "+build"],
  ["v1.2.3+01", true, "v1.2.3", "+01"],
  ["v1.2.3-0a", true, "v1.2.3-0a", ""],
  ["v1.2.3-0", true, "v1.2.3-0", ""],
  ["v1.2.3-alpha.1.beta-2", true, "v1.2.3-alpha.1.beta-2", ""],
  ["v1.2.3-x.7.z.92+b.1-2", true, "v1.2.3-x.7.z.92", "+b.1-2"],
  ["v99999999999999999999.0.0", true, "v99999999999999999999.0.0", ""],
  ["1.2.3", false, "", ""],
  ["V1.2.3", false, "", ""],
  ["v", false, "", ""],
  ["", false, "", ""],
  ["v1+build", false, "", ""],
  ["v1.2+build", false, "", ""],
  ["v1-pre", false, "", ""],
  ["v1.2-pre", false, "", ""],
  ["v01.2.3", false, "", ""],
  ["v1.02.3", false, "", ""],
  ["v1.2.03", false, "", ""],
  ["v1.2.3-01", false, "", ""],
  ["v1.2.3-a..b", false, "", ""],
  ["v1.2.3-", false, "", ""],
  ["v1.2.3+", false, "", ""],
  ["v1.2.3+a.", false, "", ""],
  ["v1.2.3-a+b+c", false, "", ""],
  ["v1.2.3_x", false, "", ""],
  ["v1.2.3.4", false, "", ""],
  ["v1.2.3-é", false, "", ""],
  ["v1.", false, "", ""],
  ["v1.2.", false, "", ""],
  [" v1.2.3", false, "", ""],
  ["v1.2.3 ", false, "", ""],
];

describe("semver", () => {
  it.each(cases)("%j: valid=%s canonical=%j build=%j", (v, valid, canon, b) => {
    expect(isValid(v)).toBe(valid);
    expect(canonical(v)).toBe(canon);
    expect(build(v)).toBe(b);
  });
});
