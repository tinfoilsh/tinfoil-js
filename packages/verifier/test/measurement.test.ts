/** Tests for measurements: register parsing, expectations, formatting and cloning. */
import { describe, expect, it } from "vitest";
import {
  cloneExpected,
  formatMeasurement,
  parseExpectedSevSnp,
  parseExpectedTdx,
  parseRegister,
  REGISTER_SIZE,
  registerHex,
  type Expected,
  type Register,
  type SevSnpMeasurement,
  type TdxMeasurement,
} from "../src/measurement.js";

/** A register with the given leading bytes, zero-padded to 48. */
function reg(...prefix: number[]): Register {
  const r = new Uint8Array(REGISTER_SIZE);
  r.set(prefix);
  return r;
}

const tdxFixture = (): TdxMeasurement => ({
  platform: "tdx",
  mrtd: reg(1),
  rtmr0: reg(2),
  rtmr1: reg(3),
  rtmr2: reg(4),
  rtmr3: reg(5),
});

describe("measurement", () => {
  describe("parseRegister", () => {
    const want = reg(0xab, 0xcd);
    const lower = "abcd" + "00".repeat(REGISTER_SIZE - 2);
    it.each([lower, lower.toUpperCase()])("accepts %s", (input) => {
      expect(parseRegister(input)).toEqual(want);
    });
    it("the text form is lowercase", () => {
      expect(registerHex(want)).toBe(lower);
    });
    // The length is checked before decoding.
    it.each([
      ["not hex", "zz".repeat(REGISTER_SIZE), "not hex"],
      ["too short", "ab".repeat(REGISTER_SIZE - 1), "96 hex characters"],
      ["too long", "ab".repeat(REGISTER_SIZE + 1), "96 hex characters"],
      ["too long, no hex", "zz".repeat(REGISTER_SIZE + 1), "96 hex characters"],
      ["empty", "", "96 hex characters"],
    ])("%s", (_name, input, err) => {
      expect(() => parseRegister(input)).toThrow(err);
    });
  });

  // Registers are plain Uint8Arrays with no JSON codec, so there is no text
  // round trip to test.
  it.skip("register text round trip (no JSON text codec for registers in TS)", () => {});

  it("parseExpectedTdx and parseExpectedSevSnp read registers in order, leaving empty ones unset", () => {
    const tdx = tdxFixture();
    const all = parseExpectedTdx(
      registerHex(tdx.mrtd),
      registerHex(tdx.rtmr0),
      registerHex(tdx.rtmr1),
      registerHex(tdx.rtmr2),
      registerHex(tdx.rtmr3),
    );
    // A measurement with every register set is the expectation that pins each of them.
    expect(all, "arguments are in register order").toEqual(tdx);
    const sparse = parseExpectedTdx("", "", "", "", registerHex(tdx.rtmr3).toUpperCase());
    expect(sparse, `"" leaves a register unconstrained`).toEqual({ platform: "tdx", rtmr3: tdx.rtmr3 });

    const sev: SevSnpMeasurement = { platform: "sev-snp", launch: reg(1) };
    expect(parseExpectedSevSnp(registerHex(sev.launch))).toEqual(sev);
    expect(parseExpectedSevSnp("")).toEqual({ platform: "sev-snp" });

    expect(() => parseExpectedTdx("", "", "", "abcd", "")).toThrow("RTMR2: register must be 96 hex characters");
    expect(() => parseExpectedSevSnp("zz".repeat(REGISTER_SIZE))).toThrow("Launch: register is not hex");
  });

  it("formatMeasurement lists one labeled register per line", () => {
    const register = reg(0xab);
    expect(formatMeasurement({ platform: "sev-snp", launch: register })).toBe(
      "SEV-SNP\nLaunch " + registerHex(register),
    );
    expect(formatMeasurement({ platform: "tdx", rtmr1: register })).toBe(
      "TDX\nMRTD   any\nRTMR0  any\nRTMR1  " + registerHex(register) + "\nRTMR2  any\nRTMR3  any",
    );
  });

  it("cloneExpected shares no registers with the original", () => {
    const register = reg(0xab);
    for (const original of [
      { platform: "sev-snp", launch: register },
      { platform: "tdx", rtmr1: register },
    ] as Expected[]) {
      const clone = cloneExpected(original);
      expect(clone).toEqual(original);
      register[0] = 0xcd;
      expect(clone, "changing the original's register must not reach the clone").not.toEqual(original);
      register[0] = 0xab;
    }
    expect(cloneExpected({ platform: "tdx" }), "unconstrained registers stay unset").toEqual({ platform: "tdx" });
  });
});
