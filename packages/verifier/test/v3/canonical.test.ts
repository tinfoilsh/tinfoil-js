import { describe, expect, it } from "vitest";
import { decodeBase64, decodeLowerHex, isLowerHex } from "../../src/v3/internal/canonical.js";

// Expected results confirmed against Go 1.27.3: base64.StdEncoding.Strict()
// followed by the EncodeToString round trip, and encoding/hex.

describe("isLowerHex", () => {
  it.each([[""], ["0"], ["0123456789abcdef"], ["abc"]])("accepts %j", (s) => {
    expect(isLowerHex(s)).toBe(true);
  });
  it.each([["ABCDEF"], ["aB"], ["g0"], ["00\n"], ["\n00"], [" 00"], ["0x00"], ["é"]])("rejects %j", (s) => {
    expect(isLowerHex(s)).toBe(false);
  });
});

describe("decodeLowerHex", () => {
  it("decodes exact-length lowercase hex", () => {
    expect(decodeLowerHex("f", "00ff10ab", 4)).toEqual(Uint8Array.from([0x00, 0xff, 0x10, 0xab]));
    expect(decodeLowerHex("f", "", 0)).toEqual(new Uint8Array(0));
  });
  it("rejects uppercase hex", () => {
    expect(() => decodeLowerHex("f", "00FF", 2)).toThrow("f is not lowercase hex");
    expect(() => decodeLowerHex("f", "00fF", 2)).toThrow("f is not lowercase hex");
  });
  it("rejects odd length", () => {
    expect(() => decodeLowerHex("f", "abc", 2)).toThrow(/f is not hex/);
  });
  it("rejects the wrong length", () => {
    expect(() => decodeLowerHex("f", "0011", 3)).toThrow("f must be 3 bytes, got 2");
    expect(() => decodeLowerHex("f", "", 1)).toThrow("f must be 1 bytes, got 0");
  });
  it("rejects non-hex characters", () => {
    expect(() => decodeLowerHex("f", "0g", 1)).toThrow(JSON.stringify("f is not lowercase hex").slice(1, -1));
    expect(() => decodeLowerHex("f", "00\n", 1)).toThrow(/not lowercase hex/);
  });
});

describe("decodeBase64", () => {
  const bytesOf = (s: string) => Uint8Array.from(Array.from(s, (c) => c.charCodeAt(0)));

  it.each([
    ["", ""],
    ["QQ==", "A"],
    ["QUI=", "AB"],
    ["QUJD", "ABC"],
    ["QUJDRA==", "ABCD"],
    ["+/8=", "\xfb\xff"],
  ])("accepts canonical %j", (s, want) => {
    expect(decodeBase64("f", s)).toEqual(bytesOf(want));
  });

  it("round-trips every byte value", () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    const b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==";
    expect(decodeBase64("f", b64)).toEqual(all);
  });

  // Rejected by Strict() itself.
  it.each([
    ["QR==", "non-zero padding bits (2-byte pad)"],
    ["QUJ=", "non-zero padding bits (1-byte pad)"],
    ["QQ", "missing padding"],
    ["QQ=", "short padding"],
    ["Q===", "too much padding"],
    ["====", "only padding"],
    ["QQ==QQ==", "padding in the middle"],
    ["QUJD====", "trailing padding quantum"],
    ["A", "truncated"],
    [" QUJD", "space"],
    ["QUJD ", "trailing space"],
    ["-_8=", "URL alphabet"],
    ["QU\tJD", "tab"],
  ])("rejects %j (%s)", (s) => {
    expect(() => decodeBase64("f", s)).toThrow(/^decoding f: /);
  });

  // Accepted by Strict() (which skips CR and LF) but caught by the round trip.
  it.each([["QUJ\nD"], ["QU\rJD"], ["QUJD\n"], ["\r\nQQ=="], ["QQ=\n="]])("rejects CR/LF in %j as non-canonical", (s) => {
    expect(() => decodeBase64("f", s)).toThrow("f is not canonical base64");
  });
});
