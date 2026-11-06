/**
 * The hex helpers the package exports: `toHex` writes lowercase hex, and
 * `fromHex` reads only that form back, refusing anything else with a plain
 * error.
 */
import { describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/index.js";

describe("toHex", () => {
  it("writes lowercase hex, two digits per byte, and nothing for no bytes", () => {
    expect(toHex(new Uint8Array([0, 1, 15, 16, 171, 255]))).toBe("00010f10abff");
    expect(toHex(new Uint8Array())).toBe("");
  });
});

describe("fromHex", () => {
  it("reads lowercase hex of even length back to the same bytes", () => {
    expect(fromHex("00010f10abff")).toEqual(new Uint8Array([0, 1, 15, 16, 171, 255]));
    expect(fromHex("")).toEqual(new Uint8Array());
    const bytes = new Uint8Array(256);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i;
    expect(fromHex(toHex(bytes))).toEqual(bytes);
  });

  it("refuses odd length, uppercase, and anything that isn't a hex digit, with a plain error", () => {
    for (const bad of ["a", "abc", "AB", "0A", "0x0a", "zz", "a b", " ab", "ab\n"]) {
      expect(() => fromHex(bad), bad).toThrow(Error);
      expect(() => fromHex(bad), bad).toThrow(/lowercase hex/);
    }
  });
});
