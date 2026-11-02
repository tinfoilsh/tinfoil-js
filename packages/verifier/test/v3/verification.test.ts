import { describe, expect, it } from "vitest";
import type { ExpectedTdx, SevSnpMeasurement } from "../../src/v3/measurement.js";
import { Verification } from "../../src/v3/verification.js";

const reg = (fill: number) => new Uint8Array(48).fill(fill);

function makeVerification() {
  const launch = reg(1);
  const rtmr1 = reg(2);
  const v = new Verification({
    codeDigest: "d",
    codeTag: "v1.0.0",
    configRepo: "tinfoilsh/repo",
    codeMeasurement: { platform: "tdx", rtmr1 },
    enclaveMeasurement: { platform: "sev-snp", launch },
    tlsPublicKeyFP: "fp",
    hpkePublicKey: "hpke",
  });
  return { v, launch, rtmr1 };
}

describe("Verification", () => {
  it("does not alias the registers it was built from", () => {
    const { v, launch, rtmr1 } = makeVerification();
    launch.fill(0xff);
    rtmr1.fill(0xff);
    expect((v.enclaveMeasurement() as SevSnpMeasurement).launch).toEqual(reg(1));
    expect((v.codeMeasurement() as ExpectedTdx).rtmr1).toEqual(reg(2));
  });

  it("returns copies that callers cannot use to change it", () => {
    const { v } = makeVerification();
    (v.enclaveMeasurement() as SevSnpMeasurement).launch.fill(0xff);
    (v.codeMeasurement() as ExpectedTdx).rtmr1!.fill(0xff);
    expect((v.enclaveMeasurement() as SevSnpMeasurement).launch).toEqual(reg(1));
    expect((v.codeMeasurement() as ExpectedTdx).rtmr1).toEqual(reg(2));
  });

  it("keeps unset expected registers unset", () => {
    const { v } = makeVerification();
    const e = v.codeMeasurement() as ExpectedTdx;
    expect(e.mrtd).toBeUndefined();
    expect(e.rtmr0).toBeUndefined();
  });

  it("exposes its facts only through accessors", () => {
    const { v } = makeVerification();
    expect(Object.keys(v)).toEqual([]);
    expect(v.codeDigest()).toBe("d");
    expect(v.codeTag()).toBe("v1.0.0");
    expect(v.configRepo()).toBe("tinfoilsh/repo");
    expect(v.tlsPublicKeyFP()).toBe("fp");
    expect(v.hpkePublicKey()).toBe("hpke");
  });
});
