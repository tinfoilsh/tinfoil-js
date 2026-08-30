// Strict JSON decoding shared by every verifier-consumed document, a 1:1 port
// of Go verifier/internal/strictjson: unknown members rejected
// case-sensitively, duplicate member names rejected everywhere (including
// inside opaque raw subtrees), valid UTF-8 required, no trailing data.
//
// Where Go decodes into tagged structs, this module decodes against an
// explicit Schema. Scalar semantics mirror encoding/json (v1):
//   - JSON null is accepted for any schema and yields the zero value,
//   - integer fields require an integer literal (no fraction or exponent —
//     Go parses the raw literal with strconv) within the type's range,
//   - a missing struct member yields the zero value ("" / false / 0 for
//     non-pointer scalars, undefined for pointer scalars, arrays and raw,
//     an empty Map for maps, a zero struct for nested structs).
//
// Raw fields (Go json.RawMessage) are retained as the exact JSON source text.

export type Schema =
  | { kind: "string" }
  | { kind: "bool" }
  // int decodes to a JS number by default; when big is set the value is
  // carried as a bigint so 64-bit fields keep full precision (a number loses
  // integer precision above 2^53). min/max are always bigint for the range
  // check regardless.
  | { kind: "int"; min: bigint; max: bigint; pointer?: boolean; big?: boolean }
  | { kind: "raw" }
  | { kind: "array"; elem: Schema }
  | { kind: "map"; value: Schema }
  | { kind: "struct"; fields: Record<string, StructField> }
  // optstruct is a Go pointer-to-struct member: absent or null decodes to
  // undefined rather than a zero struct.
  | { kind: "optstruct"; fields: Record<string, StructField> };

export interface StructField {
  prop: string; // property name on the decoded object (camelCase)
  schema: Schema;
}

export const str: Schema = { kind: "string" };
export const bool: Schema = { kind: "bool" };
export const raw: Schema = { kind: "raw" };

export function uintSchema(bits: 8 | 32 | 64, pointer = false): Schema {
  // uint64 exceeds the safe-integer range, so it is decoded as a bigint;
  // uint8/uint32 stay JS numbers.
  return { kind: "int", min: 0n, max: (1n << BigInt(bits)) - 1n, pointer, big: bits === 64 };
}

export function intSchema(pointer = false): Schema {
  return { kind: "int", min: -(1n << 63n), max: (1n << 63n) - 1n, pointer };
}

// int64Schema decodes a signed 64-bit integer as a bigint, preserving full
// precision (a JS number is exact only up to 2^53). Use it for int64 fields
// consumed as bigint; intSchema stays a number for fields that never exceed
// the safe range (VM shape dimensions, VMPL).
export function int64Schema(pointer = false): Schema {
  return { kind: "int", min: -(1n << 63n), max: (1n << 63n) - 1n, pointer, big: true };
}

export function arrayOf(elem: Schema): Schema {
  return { kind: "array", elem };
}

export function mapOf(value: Schema): Schema {
  return { kind: "map", value };
}

export function structOf(fields: Record<string, StructField>): Schema {
  return { kind: "struct", fields };
}

export function optStructOf(fields: Record<string, StructField>): Schema {
  return { kind: "optstruct", fields };
}

export function field(prop: string, schema: Schema): StructField {
  return { prop, schema };
}

// unmarshal strictly decodes JSON text (or UTF-8 bytes) against a schema.
export function unmarshal(input: string | Uint8Array, schema: Schema): unknown {
  const text =
    typeof input === "string"
      ? input
      : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          checkUTF8(input),
        );
  const p = new parser(text);
  const v = p.parseValue(schema);
  p.skipWS();
  if (p.pos !== text.length) {
    throw new Error("trailing data");
  }
  return v;
}

function checkUTF8(b: Uint8Array): Uint8Array {
  try {
    new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b);
  } catch {
    throw new Error("input is not valid UTF-8");
  }
  return b;
}

// zeroValue is the decoded value of an absent struct member.
export function zeroValue(schema: Schema): unknown {
  switch (schema.kind) {
    case "string":
      return "";
    case "bool":
      return false;
    case "int":
      return schema.pointer ? undefined : schema.big ? 0n : 0;
    case "raw":
    case "array":
    case "optstruct":
      return undefined; // nil slice / nil RawMessage / nil pointer
    case "map":
      return new Map();
    case "struct": {
      const out: Record<string, unknown> = {};
      for (const name of Object.keys(schema.fields)) {
        const f = schema.fields[name];
        out[f.prop] = zeroValue(f.schema);
      }
      return out;
    }
  }
}

const numberRE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;
const intLiteralRE = /^-?(?:0|[1-9][0-9]*)$/;

class parser {
  readonly s: string;
  pos = 0;

  constructor(s: string) {
    this.s = s;
  }

  skipWS(): void {
    while (this.pos < this.s.length && " \t\r\n".includes(this.s[this.pos])) {
      this.pos++;
    }
  }

  peek(): string {
    this.skipWS();
    if (this.pos >= this.s.length) throw new Error("unexpected end of JSON input");
    return this.s[this.pos];
  }

  expect(c: string): void {
    if (this.peek() !== c) {
      throw new Error(`invalid character ${JSON.stringify(this.s[this.pos])}, expected ${JSON.stringify(c)}`);
    }
    this.pos++;
  }

  parseValue(schema: Schema): unknown {
    const c = this.peek();
    if (schema.kind === "raw") {
      const start = this.pos;
      this.walkRaw();
      return this.s.slice(start, this.pos);
    }
    switch (c) {
      case "n":
        this.parseKeyword("null");
        // null yields the zero value for any schema, except that arrays and
        // maps decode to nil (Go); zeroValue already models both.
        return zeroValue(schema);
      case "{":
        if (schema.kind === "struct" || schema.kind === "optstruct") {
          return this.parseStruct(schema.fields);
        }
        if (schema.kind === "map") return this.parseMap(schema.value);
        throw new Error(`cannot unmarshal object into ${schema.kind}`);
      case "[":
        if (schema.kind !== "array") {
          throw new Error(`cannot unmarshal array into ${schema.kind}`);
        }
        return this.parseArray(schema.elem);
      case '"': {
        if (schema.kind !== "string") {
          throw new Error(`cannot unmarshal string into ${schema.kind}`);
        }
        return this.parseString();
      }
      case "t":
      case "f": {
        if (schema.kind !== "bool") {
          throw new Error(`cannot unmarshal bool into ${schema.kind}`);
        }
        this.parseKeyword(c === "t" ? "true" : "false");
        return c === "t";
      }
      default: {
        const lit = this.parseNumberLiteral();
        if (schema.kind !== "int") {
          throw new Error(`cannot unmarshal number into ${schema.kind}`);
        }
        // Go parses the raw literal with strconv.Parse{Int,Uint}: a fraction,
        // exponent, or out-of-range value is a decode error.
        if (!intLiteralRE.test(lit) || (schema.min === 0n && lit.startsWith("-"))) {
          throw new Error(`cannot unmarshal number ${lit} into integer`);
        }
        const n = BigInt(lit);
        if (n < schema.min || n > schema.max) {
          throw new Error(`number ${lit} out of range`);
        }
        // A big int keeps full precision as a bigint; other ints narrow to a
        // JS number (exact within their <= 2^53 range).
        return schema.big ? n : Number(n);
      }
    }
  }

  parseStruct(fields: Record<string, StructField>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.expect("{");
    if (this.peek() === "}") {
      this.pos++;
    } else {
      for (;;) {
        const key = this.parseString();
        if (seen.has(key)) throw new Error(`duplicate object member ${JSON.stringify(key)}`);
        seen.add(key);
        const f = Object.prototype.hasOwnProperty.call(fields, key) ? fields[key] : undefined;
        if (f === undefined) throw new Error(`unknown object member ${JSON.stringify(key)}`);
        this.expect(":");
        out[f.prop] = this.parseValue(f.schema);
        const c = this.peek();
        this.pos++;
        if (c === "}") break;
        if (c !== ",") throw new Error(`invalid character ${JSON.stringify(c)} after object member`);
      }
    }
    for (const name of Object.keys(fields)) {
      const f = fields[name];
      if (!seen.has(name)) out[f.prop] = zeroValue(f.schema);
    }
    return out;
  }

  parseMap(value: Schema): Map<string, unknown> {
    const out = new Map<string, unknown>();
    this.expect("{");
    if (this.peek() === "}") {
      this.pos++;
      return out;
    }
    for (;;) {
      const key = this.parseString();
      if (out.has(key)) throw new Error(`duplicate object member ${JSON.stringify(key)}`);
      this.expect(":");
      out.set(key, this.parseValue(value));
      const c = this.peek();
      this.pos++;
      if (c === "}") return out;
      if (c !== ",") throw new Error(`invalid character ${JSON.stringify(c)} after object member`);
    }
  }

  parseArray(elem: Schema): unknown[] {
    const out: unknown[] = [];
    this.expect("[");
    if (this.peek() === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      out.push(this.parseValue(elem));
      const c = this.peek();
      this.pos++;
      if (c === "]") return out;
      if (c !== ",") throw new Error(`invalid character ${JSON.stringify(c)} in array`);
    }
  }

  // walkRaw validates a raw (schema-less) subtree, still rejecting duplicate
  // member names in every object (Go: walkStrictObject with a nil schema).
  walkRaw(): void {
    const c = this.peek();
    switch (c) {
      case "{": {
        this.pos++;
        const seen = new Set<string>();
        if (this.peek() === "}") {
          this.pos++;
          return;
        }
        for (;;) {
          const key = this.parseString();
          if (seen.has(key)) throw new Error(`duplicate object member ${JSON.stringify(key)}`);
          seen.add(key);
          this.expect(":");
          this.walkRaw();
          const d = this.peek();
          this.pos++;
          if (d === "}") return;
          if (d !== ",") throw new Error(`invalid character ${JSON.stringify(d)} after object member`);
        }
      }
      case "[": {
        this.pos++;
        if (this.peek() === "]") {
          this.pos++;
          return;
        }
        for (;;) {
          this.walkRaw();
          const d = this.peek();
          this.pos++;
          if (d === "]") return;
          if (d !== ",") throw new Error(`invalid character ${JSON.stringify(d)} in array`);
        }
      }
      case '"':
        this.parseString();
        return;
      case "t":
        this.parseKeyword("true");
        return;
      case "f":
        this.parseKeyword("false");
        return;
      case "n":
        this.parseKeyword("null");
        return;
      default:
        this.parseNumberLiteral();
        return;
    }
  }

  parseString(): string {
    if (this.peek() !== '"') {
      throw new Error("object member name is not a string");
    }
    const start = this.pos;
    this.pos++; // opening quote
    while (this.pos < this.s.length) {
      const c = this.s[this.pos];
      if (c === "\\") {
        this.pos += 2;
        continue;
      }
      if (c === '"') {
        this.pos++;
        const token = this.s.slice(start, this.pos);
        // JSON.parse validates escapes and control characters; Go additionally
        // replaces unpaired surrogates with U+FFFD, which collapses distinct
        // lone-surrogate member names into duplicates — mirror that.
        return replaceLoneSurrogates(JSON.parse(token) as string);
      }
      this.pos++;
    }
    throw new Error("unexpected end of string literal");
  }

  parseKeyword(kw: string): void {
    this.skipWS();
    if (this.s.startsWith(kw, this.pos)) {
      this.pos += kw.length;
      return;
    }
    throw new Error(`invalid character ${JSON.stringify(this.s[this.pos])} in literal`);
  }

  parseNumberLiteral(): string {
    this.skipWS();
    const m = numberRE.exec(this.s.slice(this.pos));
    if (!m) {
      throw new Error(`invalid character ${JSON.stringify(this.s[this.pos])} looking for value`);
    }
    this.pos += m[0].length;
    return m[0];
  }
}

// replaceLoneSurrogates mirrors Go's UTF-8 coercion: any unpaired surrogate
// code unit becomes U+FFFD; valid pairs pass through.
function replaceLoneSurrogates(s: string): string {
  if (!/[\uD800-\uDFFF]/.test(s)) return s;
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        out += s[i] + s[i + 1];
        i++;
        continue;
      }
    }
    out += c >= 0xd800 && c <= 0xdfff ? "\uFFFD" : s[i];
  }
  return out;
}
