import { describe, expect, it } from "vitest";
import { arr, bool, num, object, raw, str } from "../src/internal/json/decode.js";
import {
  JsonError,
  JsonNumber,
  canonicalize,
  cloneJsonValue,
  serialize,
  sourceText,
  strictParse,
  type JsonObject,
  type JsonValue,
} from "../src/internal/json/index.js";

const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const bytes = (...parts: (string | number[])[]) => {
  const out: number[] = [];
  for (const p of parts) out.push(...(typeof p === "string" ? Array.from(utf8(p)) : p));
  return Uint8Array.from(out);
};
const parse = (s: string) => strictParse(utf8(s));
const parseObj = (s: string) => parse(s) as JsonObject;
const canon = (s: string) => text(canonicalize(parse(s)));

describe("strictParse grammar", () => {
  it.each([
    ["{}"],
    [" {} \t\r\n"],
    ["1"],
    ["-0"],
    ["1E+2"],
    ["1.5e-7"],
    ["true "],
    ['"\\/"'],
    ['"\u007f"'],
    ['"é"'],
    ['{"a":1,"A":2}'],
    ['[{"a":1},{"a":2}]'],
    ["[]"],
    ['[1,[2,{"x":[null,true,false]}]]'],
  ])("accepts %j", (s) => {
    expect(() => parse(s)).not.toThrow();
  });

  it.each([
    [""],
    [" "],
    ["{} x"],
    ["{}{}"],
    ["01"],
    ["-01"],
    ["[01]"],
    ["1."],
    [".1"],
    ["1e"],
    ["1e+"],
    ["-"],
    ["+1"],
    ["NaN"],
    ["Infinity"],
    ["nul"],
    ["True"],
    ["[1,]"],
    ['{"a":1,}'],
    ["{a:1}"],
    ["{'a':1}"],
    ['{"a" 1}'],
    ["[1 2]"],
    [" {}"],
    ["\f{}"],
    ["\x00"],
    ['"\x01"'],
    ['"a\nb"'],
    ['"\\x"'],
    ['"\\U0041"'],
    ['"\\u00"'],
    ['"\\u00g0"'],
    ['"abc'],
    ["[1"],
    ['{"a":1'],
  ])("rejects %j", (s) => {
    expect(() => parse(s)).toThrow(JsonError);
  });

  it("rejects a leading byte-order mark", () => {
    expect(() => strictParse(bytes([0xef, 0xbb, 0xbf], "{}"))).toThrow(JsonError);
  });

  it("enforces the max nesting depth of 10000", () => {
    const arrays = (n: number) => "[".repeat(n) + "]".repeat(n);
    const objects = (n: number) => '{"a":'.repeat(n) + "1" + "}".repeat(n);
    expect(() => parse(arrays(10000))).not.toThrow();
    expect(() => parse(arrays(10001))).toThrow(JsonError);
    expect(() => parse(objects(10000))).not.toThrow();
    expect(() => parse(objects(10001))).toThrow(JsonError);
    expect(() => parse(arrays(100000))).toThrow(JsonError);
  });

  it("builds Maps in member order, arrays, and raw-literal numbers", () => {
    const v = parseObj('{"z":[1,"x",null,true],"a":{"n":-1.50e3},"__proto__":false}');
    expect([...v.keys()]).toEqual(["z", "a", "__proto__"]);
    const z = v.get("z") as JsonValue[];
    expect(z[0]).toBeInstanceOf(JsonNumber);
    expect((z[0] as JsonNumber).raw).toBe("1");
    expect(z.slice(1)).toEqual(["x", null, true]);
    expect(((v.get("a") as JsonObject).get("n") as JsonNumber).raw).toBe("-1.50e3");
    expect(v.get("__proto__")).toBe(false);
  });

  it("keeps integers above 2^53 exact", () => {
    const n = parse("18446744073709551615") as JsonNumber;
    expect(n.raw).toBe("18446744073709551615");
    expect(n.toBigInt()).toBe(18446744073709551615n);
  });
});

describe("strictParse duplicate names", () => {
  it.each([
    ['{"a":1,"a":2}'],
    ['{"a":1,"\\u0061":2}'],
    ['{"\\u00e9":1,"é":2}'],
    ['{"\\ud800\\udc00":1,"\u{10000}":2}'],
    ['{"a":{"b":1,"b":2}}'],
    ['[{"x":[{"y":1,"y":1}]}]'],
    ['{"a":1,"b":2,"a":3}'],
  ])("rejects %j", (s) => {
    expect(() => parse(s)).toThrow(/duplicate/);
  });

  it("is case-sensitive and per object", () => {
    expect(() => parse('{"a":1,"A":2}')).not.toThrow();
    expect(() => parse('{"a":{"a":1},"b":{"a":2}}')).not.toThrow();
  });
});

describe("strictParse strings and UTF-8", () => {
  it("decodes escapes", () => {
    expect(parse('"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\u00E9\\uD83D\\uDE00"')).toBe('"\\/\b\f\n\r\tAé😀');
  });

  it("decodes multi-byte UTF-8", () => {
    expect(parse('"é€😀"')).toBe("é€😀");
  });

  it.each([
    ['"\\ud800"'],
    ['"\\udc00"'],
    ['"\\ud800\\u0041"'],
    ['"\\ud800x"'],
    ['"\\udc00\\ud800"'],
    ['"\\ud800\\ud800"'],
    ['"\\ud800\\'],
  ])("rejects the unpaired surrogate escape %j", (s) => {
    expect(() => parse(s)).toThrow(JsonError);
  });

  it.each([
    ["lone continuation byte", [0xff]],
    ["overlong '/'", [0xc0, 0xaf]],
    ["overlong 3-byte", [0xe0, 0x80, 0x80]],
    ["UTF-8-encoded surrogate", [0xed, 0xa0, 0x80]],
    ["above U+10FFFF", [0xf4, 0x90, 0x80, 0x80]],
    ["truncated sequence", [0xe2, 0x82]],
    ["bare continuation", [0x80]],
    ["0xF5 lead byte", [0xf5, 0x80, 0x80, 0x80]],
  ])("rejects invalid UTF-8 inside a string: %s", (_, bad) => {
    expect(() => strictParse(bytes('"', bad as number[], '"'))).toThrow(JsonError);
  });

  it("rejects invalid UTF-8 outside strings", () => {
    expect(() => strictParse(bytes("[1,", [0xff], "]"))).toThrow(JsonError);
    expect(() => strictParse(bytes("{}", [0xc3]))).toThrow(JsonError);
  });

  it("accepts the edges of the valid UTF-8 ranges", () => {
    expect(strictParse(bytes('"', [0xed, 0x9f, 0xbf], '"'))).toBe("퟿");
    expect(strictParse(bytes('"', [0xf4, 0x8f, 0xbf, 0xbf], '"'))).toBe("\u{10ffff}");
    expect(strictParse(bytes('"', [0xef, 0xbb, 0xbf], '"'))).toBe("﻿");
  });
});

describe("JsonNumber", () => {
  const n = (s: string) => new JsonNumber(s);

  it("toSafeInteger accepts integer literals", () => {
    expect(n("0").toSafeInteger()).toBe(0);
    expect(Object.is(n("-0").toSafeInteger(), 0)).toBe(true);
    expect(n("-42").toSafeInteger()).toBe(-42);
    expect(n("9007199254740991").toSafeInteger()).toBe(9007199254740991);
    expect(n("-9007199254740991").toSafeInteger()).toBe(-9007199254740991);
  });

  it.each([["1.0"], ["1e2"], ["1E2"], ["1.5"], ["0e0"], ["9007199254740992"], ["-9007199254740992"], ["01"], ["abc"], [""]])(
    "toSafeInteger rejects %j",
    (s) => {
      expect(() => n(s).toSafeInteger()).toThrow(JsonError);
    },
  );

  it("toBigInt handles any size and rejects fractions, exponents and non-JSON forms", () => {
    expect(n("9223372036854775807").toBigInt()).toBe(9223372036854775807n);
    expect(n("-9223372036854775809").toBigInt()).toBe(-9223372036854775809n);
    expect(n("18446744073709551616").toBigInt()).toBe(18446744073709551616n);
    expect(n("-0").toBigInt()).toBe(0n);
    for (const s of ["1.0", "1e2", "1.5", "-1E+0", "+1", "0x10", " 1"]) {
      expect(() => n(s).toBigInt()).toThrow(JsonError);
    }
  });

  it("toFloat64 rounds correctly, underflows to zero and keeps the sign of -0", () => {
    expect(n("0.1").toFloat64()).toBe(0.1);
    expect(Object.is(n("-0").toFloat64(), -0)).toBe(true);
    expect(n("1e-400").toFloat64()).toBe(0);
    expect(n("4.9e-324").toFloat64()).toBe(5e-324);
    expect(n("2.4703282292062327e-324").toFloat64()).toBe(0);
    expect(n("2.4703282292062328e-324").toFloat64()).toBe(5e-324);
    expect(n("1.7976931348623158e308").toFloat64()).toBe(Number.MAX_VALUE);
    expect(n("9007199254740993").toFloat64()).toBe(9007199254740992);
    expect(n("1E+2").toFloat64()).toBe(100);
  });

  it.each([["1e400"], ["-1e400"], ["1.7976931348623159e308"], ["NaN"], ["Infinity"], ["0x10"], [""]])(
    "toFloat64 rejects %j",
    (s) => {
      expect(() => n(s).toFloat64()).toThrow(JsonError);
    },
  );
});

describe("canonicalize", () => {
  it("RFC 8785 section 3.2.4 example", () => {
    const input =
      '{\n  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],\n' +
      '  "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",\n' +
      '  "literals": [null, true, false]\n}';
    expect(canon(input)).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  it("RFC 8785 section 3.2.3 sorting example", () => {
    const input = '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}';
    const keys = [...(strictParse(canonicalize(parse(input))) as JsonObject).keys()];
    expect(keys).toEqual(["\r", "1", "\u0080", "ö", "€", "😀", "דּ"]);
    expect(canon(input)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  // RFC 8785 Appendix B number vectors; inputs are the IEEE values printed with
  // 17 fractional digits, outputs are the canonical forms.
  it.each([
    ["0.00000000000000000e+00", "0"],
    ["-0.00000000000000000e+00", "0"],
    ["4.94065645841246544e-324", "5e-324"],
    ["-4.94065645841246544e-324", "-5e-324"],
    ["1.79769313486231571e+308", "1.7976931348623157e+308"],
    ["-1.79769313486231571e+308", "-1.7976931348623157e+308"],
    ["9.00719925474099200e+15", "9007199254740992"],
    ["-9.00719925474099200e+15", "-9007199254740992"],
    ["2.95147905179352826e+20", "295147905179352830000"],
    ["9.99999999999999748e+22", "9.999999999999997e+22"],
    ["9.99999999999999916e+22", "1e+23"],
    ["1.00000000000000008e+23", "1.0000000000000001e+23"],
    ["9.99999999999999738e+20", "999999999999999700000"],
    ["9.99999999999999869e+20", "999999999999999900000"],
    ["1.00000000000000000e+21", "1e+21"],
    ["9.99999999999999743e-07", "9.999999999999997e-7"],
    ["9.99999999999999955e-07", "0.000001"],
    ["3.33333333333333194e+08", "333333333.3333332"],
    ["3.33333333333333254e+08", "333333333.33333325"],
    ["3.33333333333333313e+08", "333333333.3333333"],
    ["3.33333333333333373e+08", "333333333.3333334"],
    ["3.33333333333333433e+08", "333333333.33333343"],
    ["-3.33333333333333332e-06", "-0.0000033333333333333333"],
    ["1.42495392378120625e+15", "1424953923781206.2"],
  ])("number %s -> %s", (input, want) => {
    expect(canon(input)).toBe(want);
  });

  it.each([
    ["-0", "0"],
    ["-0.0", "0"],
    ["1.0", "1"],
    ["1e20", "100000000000000000000"],
    ["1E+30", "1e+30"],
    ["1e-7", "1e-7"],
    ["0.000001", "0.000001"],
    ["123456789012345678901234567890", "1.2345678901234568e+29"],
    ["9007199254740993", "9007199254740992"],
    ["12345678901234567890", "12345678901234567000"],
    ["0.1e1", "1"],
    ["1e400", "1.7976931348623157e+308"],
    ["-1e400", "-1.7976931348623157e+308"],
    ["1e-400", "0"],
    ["-1e-400", "0"],
  ])("number %s -> %s", (input, want) => {
    expect(canon(input)).toBe(want);
  });

  it("uses minimal string escaping", () => {
    expect(canon('"\\u0000\\u001e\\u001F\\u007f\\u0080\\u2028\\u2029<>&\\ud83d\\ude00\\/\\ufeff"')).toBe(
      '"\\u0000\\u001e\\u001f\u007f\u0080  <>&😀/﻿"',
    );
    expect(canon('"\\b\\f\\n\\r\\t\\"\\\\"')).toBe('"\\b\\f\\n\\r\\t\\"\\\\"');
  });

  it("sorts members at every depth and removes whitespace", () => {
    expect(canon('{"b":[],"a":{},"":null,"A":0}')).toBe('{"":null,"A":0,"a":{},"b":[]}');
    expect(canon('[\n 1 , {"y":1, "x":{"d":1,"c":2}} ]')).toBe('[1,{"x":{"c":2,"d":1},"y":1}]');
  });

  it("is idempotent", () => {
    const once = canonicalize(parse('{"b":1.50,"a":"\\u00e9","c":[1E2]}'));
    expect(text(canonicalize(strictParse(once)))).toBe(text(once));
  });

  it("rejects values it cannot encode", () => {
    expect(() => canonicalize("\ud800")).toThrow(JsonError);
    expect(() => canonicalize(new JsonNumber("01"))).toThrow(JsonError);
    expect(() => canonicalize(new JsonNumber("NaN"))).toThrow(JsonError);
  });

  it("writes 10000-deep values without overflowing the stack", () => {
    let v: JsonValue = [];
    for (let i = 1; i < 10000; i++) v = [v];
    expect(text(canonicalize(v))).toBe("[".repeat(10000) + "]".repeat(10000));
  });
});

describe("serialize", () => {
  it("is compact and preserves member order and number literals", () => {
    expect(text(serialize(parse('{ "b" : 1.50 , "a" : [ 1E2 , -0 , 18446744073709551616 ] , "c":{} }')))).toBe(
      '{"b":1.50,"a":[1E2,-0,18446744073709551616],"c":{}}',
    );
  });

  it("re-escapes strings minimally and round-trips", () => {
    const s = '{"k\\u00e9\\/":"\\u0001\\n\\"\\\\\\ud83d\\ude00 "}';
    const out = text(serialize(parse(s)));
    expect(out).toBe('{"ké/":"\\u0001\\n\\"\\\\😀 "}');
    expect(strictParse(utf8(out))).toEqual(parse(s));
  });

  it("serializes scalars", () => {
    expect(text(serialize(null))).toBe("null");
    expect(text(serialize(true))).toBe("true");
    expect(text(serialize("x"))).toBe('"x"');
    expect(text(serialize(new JsonNumber("-1.5e-3")))).toBe("-1.5e-3");
  });

  it("rejects lone surrogates and invalid number literals", () => {
    expect(() => serialize(["\udc00"])).toThrow(JsonError);
    expect(() => serialize(new JsonNumber("1."))).toThrow(JsonError);
  });
});

describe("sourceText", () => {
  it("is each parsed object's span, untouched, at every depth", () => {
    const inner = `{ "k\\u00e9" : [ 1.50 , { } , "}" ] ,\n "é😀":{"x":null} }`;
    const s = `{"a":${inner},"b":[${inner}],"c":{}}`;
    const root = parseObj(s);
    expect(sourceText(root)).toBe(s);
    expect(sourceText(root.get("a") as JsonObject)).toBe(inner);
    expect(sourceText((root.get("b") as JsonValue[])[0] as JsonObject)).toBe(inner);
    expect(sourceText(root.get("c") as JsonObject)).toBe("{}");
    const nested = (root.get("a") as JsonObject).get("é😀") as JsonObject;
    expect(sourceText(nested)).toBe(`{"x":null}`);
    expect(sourceText(((root.get("a") as JsonObject).get("ké") as JsonValue[])[1] as JsonObject)).toBe("{ }");
  });

  it("re-encodes to exactly the bytes parsed", () => {
    const prefix = utf8('{"before":"é","v":');
    const member = bytes("{\"s\":\"\\u00e9", [0xc3, 0xa9, 0xf0, 0x9f, 0x98, 0x80], '", "n":1e2}');
    const src = bytes(Array.from(prefix), Array.from(member), "}");
    const v = (strictParse(src) as JsonObject).get("v") as JsonObject;
    expect(utf8(sourceText(v)!)).toEqual(member);
  });

  it("is undefined for a copy or a hand-built Map", () => {
    const root = parseObj('{"a":{}}');
    expect(sourceText(cloneJsonValue(root) as JsonObject)).toBeUndefined();
    expect(sourceText((cloneJsonValue(root) as JsonObject).get("a") as JsonObject)).toBeUndefined();
    expect(sourceText(new Map())).toBeUndefined();
  });
});

// The decode helpers read typed members out of a parsed object: a known
// member set rejects unknown members, names match case-sensitively, and an
// absent member yields the type's empty value.
describe("decode helpers", () => {
  it("object accepts objects and treats null as an empty object", () => {
    expect(object(parse('{"a":1}'), "S").get("a")).toBeInstanceOf(JsonNumber);
    expect(object(null, "S").size).toBe(0);
    expect(object(null, "S", ["a"]).size).toBe(0);
  });

  it.each([["[]"], ['"x"'], ["1"], ["true"]])("object rejects %s", (s) => {
    expect(() => object(parse(s), "S")).toThrow(JsonError);
  });

  it("object rejects unknown members only when known is set", () => {
    const v = parse('{"a":1,"zz":2}');
    expect(() => object(v, "S", ["a"])).toThrow(/unknown object member name "zz"/);
    expect(() => object(v, "S", ["a", "zz"])).not.toThrow();
    expect(() => object(v, "S")).not.toThrow();
  });

  it("matches member names case-sensitively", () => {
    expect(() => object(parse('{"X":"1"}'), "T", ["x"])).toThrow(JsonError);
    const o = object(parse('{"X":"1"}'), "T");
    expect(str(o, "x")).toBe("");
    expect(str(o, "X")).toBe("1");
  });

  it("str", () => {
    const o = parseObj('{"s":"v","n":null,"num":1,"b":true,"a":[],"o":{}}');
    expect(str(o, "s")).toBe("v");
    expect(str(o, "n")).toBe("");
    expect(str(o, "absent")).toBe("");
    for (const k of ["num", "b", "a", "o"]) expect(() => str(o, k)).toThrow(JsonError);
  });

  it("bool", () => {
    const o = parseObj('{"t":true,"f":false,"n":null,"s":"true","num":1}');
    expect(bool(o, "t")).toBe(true);
    expect(bool(o, "f")).toBe(false);
    expect(bool(o, "n")).toBe(false);
    expect(bool(o, "absent")).toBe(false);
    expect(() => bool(o, "s")).toThrow(JsonError);
    expect(() => bool(o, "num")).toThrow(JsonError);
  });

  it("num", () => {
    const o = parseObj('{"p":1,"n":null,"s":"1","b":false}');
    expect(num(o, "p")?.raw).toBe("1");
    expect(num(o, "n")).toBeUndefined();
    expect(num(o, "absent")).toBeUndefined();
    expect(() => num(o, "s")).toThrow(JsonError);
    expect(() => num(o, "b")).toThrow(JsonError);
  });

  it("arr", () => {
    const o = parseObj('{"a":[1],"e":[],"n":null,"o":{},"s":"x"}');
    expect(arr(o, "a")).toHaveLength(1);
    expect(arr(o, "e")).toEqual([]);
    expect(arr(o, "n")).toBeUndefined();
    expect(arr(o, "absent")).toBeUndefined();
    expect(() => arr(o, "o")).toThrow(JsonError);
    expect(() => arr(o, "s")).toThrow(JsonError);
  });

  it("raw", () => {
    const o = parseObj('{"r":{"z":[1, 2]},"n":null}');
    expect(text(serialize(raw(o, "r")!))).toBe('{"z":[1,2]}');
    expect(raw(o, "n")).toBeNull();
    expect(raw(o, "absent")).toBeUndefined();
  });
});

describe("review regressions", () => {
  it("keeps a number literal too long to spread into function arguments", () => {
    const digits = "1".repeat(500_000);
    const v = parse(digits);
    expect(v).toBeInstanceOf(JsonNumber);
    expect((v as JsonNumber).raw).toBe(digits);
  });
});

describe("JSON.parse-backed strictness", () => {
  it("keeps source member order, including integer-like names", () => {
    const keys = [...(parse('{"b":1,"10":2,"a":3,"2":4}') as JsonObject).keys()];
    expect(keys).toEqual(["b", "10", "a", "2"]);
    expect(text(serialize(parse('{"z":{"9":1,"x":2},"1":[{"5":0,"0":1}]}')))).toBe('{"z":{"9":1,"x":2},"1":[{"5":0,"0":1}]}');
  });

  it("treats __proto__ and constructor as ordinary member names", () => {
    const v = parse('{"__proto__":{"polluted":1},"constructor":2}') as JsonObject;
    expect([...v.keys()]).toEqual(["__proto__", "constructor"]);
    expect((v.get("__proto__") as JsonObject).get("polluted")).toBeInstanceOf(JsonNumber);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(() => parse('{"__proto__":1,"__proto__":2}')).toThrow(JsonError);
  });

  it("finds duplicates behind strings that contain braces, quotes and colons", () => {
    expect(() => parse('{"a":"}{\\"","a":1}')).toThrow(JsonError);
    expect(() => parse('{"x":["a:",{"a":1,"a":2}]}')).toThrow(JsonError);
    expect(() => parse('{"a:":1,"b":"\\"a\\":","a:":2}')).toThrow(JsonError);
    expect(() => parse('{"a":"a","b":{"a":1}}')).not.toThrow();
    expect(() => parse('["a","a",{"k":"k"}]')).not.toThrow();
  });
});

describe("cloneJsonValue", () => {
  it("shares no containers with the original", () => {
    const v = parse('{"a":[1,{"b":"x"}],"c":{"d":[[]]}}') as JsonObject;
    const c = cloneJsonValue(v) as JsonObject;
    expect(c).toEqual(v);
    expect(c).not.toBe(v);
    (c.get("a") as JsonValue[]).push("extra");
    ((c.get("c") as JsonObject).get("d") as JsonValue[][])[0]!.push(null);
    expect((v.get("a") as JsonValue[]).length).toBe(2);
    expect(((v.get("c") as JsonObject).get("d") as JsonValue[][])[0]!.length).toBe(0);
    expect(cloneJsonValue(null)).toBeNull();
  });
});
