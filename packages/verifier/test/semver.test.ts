import { describe, expect, it } from "vitest";
import { build, canonical, compare, isValid } from "../src/internal/semver.js";

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

/** Versions in ascending precedence; the versions of one row are equal. */
const ascending: string[][] = [
  ["bad", "", "1.0.0", "v1-pre", "v1.2+meta", "v1.2.3-01"],
  ["v0.15.4"],
  ["v0.15.5-rc.0"],
  ["v0.15.5-rc.1", "v0.15.5-rc.1+gpu"],
  ["v0.15.5-rc.1.0"],
  ["v0.15.5-rc.2"],
  ["v0.15.5-rc.10"],
  ["v0.15.5-rc.a"],
  ["v0.15.5-rd"],
  ["v0.15.5", "v0.15.5+gpu"],
  ["v0.15.10"],
  ["v0.16", "v0.16.0"],
  ["v1.0.0-alpha"],
  ["v1.0.0-alpha.1"],
  ["v1.0.0-alpha.beta"],
  ["v1.0.0-beta"],
  ["v1.0.0-beta.2"],
  ["v1.0.0-beta.11"],
  ["v1.0.0-rc.1"],
  ["v1", "v1.0", "v1.0.0", "v1.0.0+meta-pre.sha.256a"],
  ["v1.2.3-456"],
  ["v1.2.3-456.789"],
  ["v1.2.3-456-789"],
  ["v1.2.3-456a"],
  ["v1.2.3-Pre"],
  ["v1.2.3-pre", "v1.2.3-pre+meta"],
  ["v1.2.3-pre.1"],
  ["v1.2.3-zzz"],
  ["v1.2.3", "v1.2.3+meta"],
  ["v9.0.0"],
  ["v10.0.0"],
  ["v99999999999999999999.0.0"],
  ["v100000000000000000000.0.0"],
];

describe("semver", () => {
  it.each(cases)("%j: valid=%s canonical=%j build=%j", (v, valid, canon, b) => {
    expect(isValid(v)).toBe(valid);
    expect(canonical(v)).toBe(canon);
    expect(build(v)).toBe(b);
  });

  it("orders versions by precedence, ignoring build metadata", () => {
    ascending.forEach((row, i) => {
      ascending.forEach((other, j) => {
        for (const v of row) {
          for (const w of other) expect(Math.sign(compare(v, w)), `${JSON.stringify(v)} against ${JSON.stringify(w)}`).toBe(Math.sign(i - j));
        }
      });
    });
  });
});
