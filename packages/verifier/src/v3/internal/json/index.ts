/**
 * Strict JSON with Go encoding/json/v2 semantics, which the reference
 * verifier relies on throughout:
 *
 * - invalid UTF-8 rejects, as does a leading byte-order mark;
 * - escaped surrogates must form a valid pair (`"\ud800"` rejects);
 * - duplicate member names reject at any depth, compared on decoded names;
 * - trailing data after the top-level value rejects;
 * - nesting deeper than 10000 rejects (jsontext's maxNestingDepth); the
 *   engine's own reviver recursion limit (about 2300 levels in V8) also
 *   rejects, so pathologically deep input Go accepts is rejected here;
 * - numbers keep their raw literal so u64 fields survive above 2^53.
 *
 * Parsing is JSON.parse plus checks: TextDecoder handles UTF-8, the reviver
 * keeps number literals, a name scan rejects duplicates, and a final walk
 * rejects lone surrogates. Unknown-member rejection is per struct in Go, so
 * it lives in the decoders (see decode.ts), not here.
 */

/** A parsed JSON value. Objects are Maps so member names can't collide with Object.prototype. */
export type JsonValue = null | boolean | JsonNumber | string | readonly JsonValue[] | JsonObject;
export type JsonObject = ReadonlyMap<string, JsonValue>;

/** RFC 8259 number grammar. */
const NUMBER_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/;
/** The subset Go's jsonwire.ParseUint (with optional '-') accepts for integer fields. */
const INTEGER_RE = /^-?(?:0|[1-9][0-9]*)$/;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** A JSON number, kept as its source literal. */
export class JsonNumber {
  constructor(readonly raw: string) {}

  /**
   * The number as an integer, if the literal is one (no fraction or exponent) within ±(2^53-1).
   * Go rejects "1.0" and "1e2" for integer fields; "-0" is 0.
   */
  toSafeInteger(): number {
    const n = this.toBigInt();
    if (n > MAX_SAFE || n < -MAX_SAFE) {
      throw new JsonError(`JSON number ${this.raw} is out of range`);
    }
    return Number(n);
  }

  /**
   * The number as an integer of any size, if the literal is one. "-0" yields 0n;
   * Go rejects any leading '-' for unsigned fields, so uint64 callers must check
   * `raw` for a sign as well as range-checking the result.
   */
  toBigInt(): bigint {
    if (!INTEGER_RE.test(this.raw)) {
      throw new JsonError(`JSON number ${this.raw} is not an integer`);
    }
    return BigInt(this.raw);
  }

  /**
   * The literal's float64 value, as Go's strconv.ParseFloat gives it (and so
   * json v2 and protojson/structpb): correctly rounded, underflow to ±0 is
   * fine, overflow to ±Inf is an error.
   */
  toFloat64(): number {
    const f = parseNumber(this.raw);
    if (!isFinite(f)) {
      throw new JsonError(`JSON number ${this.raw} is out of range`);
    }
    return f;
  }
}

/** A JSON syntax or strictness violation. */
export class JsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JsonError";
  }
}

/** jsontext's maxNestingDepth. */
const MAX_DEPTH = 10000;

/** Parses exactly one JSON value from UTF-8 bytes. Throws JsonError. */
export function strictParse(bytes: Uint8Array): JsonValue {
  let text: string;
  try {
    // fatal: invalid UTF-8 rejects. ignoreBOM: a leading BOM stays in the
    // text, where JSON.parse rejects it as Go does.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new JsonError("invalid UTF-8");
  }

  let parsed: unknown;
  try {
    // JSON.parse enforces the RFC 8259 grammar and rejects trailing data. The
    // reviver keeps each number's source literal (TC39 JSON.parse source text
    // access) so integers beyond 2^53 and "1" vs "1.0" stay distinguishable.
    parsed = JSON.parse(text, (_key: string, value: unknown, context?: { source?: string }) => {
      if (typeof value !== "number") return value;
      if (context?.source === undefined) {
        throw new JsonError("this JavaScript engine lacks JSON.parse source text access");
      }
      return new JsonNumber(context.source);
    });
  } catch (err) {
    if (err instanceof JsonError) throw err;
    // A RangeError here is the engine's own recursion limit in the reviver,
    // which is lower than MAX_DEPTH; such input is rejected, never accepted.
    throw new JsonError(`invalid JSON: ${(err as Error).message}`);
  }

  return toJsonValue(parsed, checkNames(text));
}

/**
 * Rejects duplicate member names (compared after unescaping) and nesting
 * deeper than MAX_DEPTH, and returns each object's member names in source
 * order, objects listed in document (pre-)order. JSON.parse keeps only the
 * last duplicate and lists integer-like names first, so this scans the text
 * it has already validated: it only tracks nesting and decodes each string
 * that is followed by ':' (a member name).
 */
function checkNames(text: string): string[][] {
  const orders: string[][] = [];
  const stack: ({ readonly seen: Set<string>; readonly order: string[] } | null)[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x7b /* { */ || c === 0x5b /* [ */) {
      if (stack.length >= MAX_DEPTH) throw new JsonError("exceeded max depth");
      if (c === 0x7b) {
        const order: string[] = [];
        orders.push(order);
        stack.push({ seen: new Set(), order });
      } else {
        stack.push(null);
      }
    } else if (c === 0x7d /* } */ || c === 0x5d /* ] */) {
      stack.pop();
    } else if (c === 0x22 /* " */) {
      const start = i;
      for (i++; text.charCodeAt(i) !== 0x22; i++) {
        if (text.charCodeAt(i) === 0x5c /* \ */) i++;
      }
      let j = i + 1;
      while (j < text.length && " \t\n\r".indexOf(text[j]!) >= 0) j++;
      const top = stack[stack.length - 1];
      if (text[j] === ":" && top) {
        const name = JSON.parse(text.slice(start, i + 1)) as string;
        if (top.seen.has(name)) throw new JsonError(`duplicate object member name ${JSON.stringify(name)}`);
        top.seen.add(name);
        top.order.push(name);
      }
    }
  }
  return orders;
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function checkString(s: string): string {
  // Valid UTF-8 can't encode a surrogate, so a lone one came from an escape
  // such as "\ud800", which Go rejects.
  if (LONE_SURROGATE.test(s)) throw new JsonError("invalid escaped surrogate in string");
  return s;
}

/**
 * Converts JSON.parse output to JsonValue without recursion: objects become
 * Maps (so names can't collide with Object.prototype) in source member order
 * (from `orders`, consumed in document order), and every string and member
 * name is checked for lone surrogates.
 */
function toJsonValue(root: unknown, orders: readonly string[][]): JsonValue {
  let next = 0;
  type Frame = { readonly src: Record<string, unknown> | unknown[]; readonly keys: string[]; idx: number; readonly out: Map<string, JsonValue> | JsonValue[] };
  const convert = (v: unknown): JsonValue | Frame => {
    if (v === null || typeof v === "boolean" || v instanceof JsonNumber) return v;
    if (typeof v === "string") return checkString(v);
    if (Array.isArray(v)) return { src: v, keys: [], idx: 0, out: [] };
    const o = v as Record<string, unknown>;
    const keys = orders[next++];
    if (keys === undefined || keys.length !== Object.keys(o).length) {
      throw new JsonError("member scan disagrees with JSON.parse");
    }
    return { src: o, keys: keys.map(checkString), idx: 0, out: new Map() };
  };
  const isFrame = (x: JsonValue | Frame): x is Frame =>
    typeof x === "object" && x !== null && !(x instanceof JsonNumber) && !(x instanceof Map) && !Array.isArray(x);

  const first = convert(root);
  if (!isFrame(first)) return first;
  const stack: Frame[] = [first];
  for (;;) {
    const f = stack[stack.length - 1]!;
    const arr = Array.isArray(f.src);
    const len = arr ? (f.src as unknown[]).length : f.keys.length;
    if (f.idx === len) {
      stack.pop();
      const done = f.out as JsonValue;
      if (stack.length === 0) return done;
      place(stack[stack.length - 1]!, done);
      continue;
    }
    const child = arr ? (f.src as unknown[])[f.idx] : (f.src as Record<string, unknown>)[f.keys[f.idx]!];
    const c = convert(child);
    if (isFrame(c)) stack.push(c);
    else place(f, c);
  }

  function place(f: Frame, v: JsonValue): void {
    if (Array.isArray(f.out)) f.out.push(v);
    else f.out.set(f.keys[f.idx]!, v);
    f.idx++;
  }
}

/** Parses a JSON number literal as float64 (round-to-nearest-even, like strconv.ParseFloat). */
function parseNumber(raw: string): number {
  if (!NUMBER_RE.test(raw)) throw new JsonError(`invalid JSON number ${JSON.stringify(raw)}`);
  return Number(raw);
}

/** Serializes a value in RFC 8785 canonical form (Go jsontext.Value.Canonicalize). */
export function canonicalize(value: JsonValue): Uint8Array {
  return write(value, true);
}

/** Serializes a value compactly, preserving member order and number literals. */
export function serialize(value: JsonValue): Uint8Array {
  return write(value, false);
}

type WriteFrame = {
  readonly items: readonly JsonValue[] | ReadonlyArray<readonly [string, JsonValue]>;
  readonly object: boolean;
  idx: number;
};

function write(root: JsonValue, canonical: boolean): Uint8Array {
  const out = new ByteWriter();
  const stack: WriteFrame[] = [];
  let v: JsonValue = root;
  for (;;) {
    let descended = false;
    if (Array.isArray(v) || v instanceof Map) {
      if (stack.length >= MAX_DEPTH) throw new JsonError("exceeded max depth");
      if (Array.isArray(v)) {
        const items = v as readonly JsonValue[];
        out.byte(0x5b);
        if (items.length === 0) {
          out.byte(0x5d);
        } else {
          stack.push({ items, object: false, idx: 0 });
          v = items[0]!;
          descended = true;
        }
      } else {
        const entries = Array.from((v as JsonObject).entries());
        if (canonical) entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
        out.byte(0x7b);
        if (entries.length === 0) {
          out.byte(0x7d);
        } else {
          stack.push({ items: entries, object: true, idx: 0 });
          writeString(out, entries[0]![0]);
          out.byte(0x3a);
          v = entries[0]![1];
          descended = true;
        }
      }
    } else if (v === null) {
      out.ascii("null");
    } else if (v === true) {
      out.ascii("true");
    } else if (v === false) {
      out.ascii("false");
    } else if (typeof v === "string") {
      writeString(out, v);
    } else if (v instanceof JsonNumber) {
      out.ascii(canonical ? canonicalNumber(v.raw) : checkedRaw(v.raw));
    } else {
      throw new JsonError("unsupported JSON value");
    }
    if (descended) continue;

    // Move to the next sibling, closing finished containers.
    for (;;) {
      const top = stack[stack.length - 1];
      if (top === undefined) return out.bytes();
      top.idx++;
      if (top.idx < top.items.length) {
        out.byte(0x2c);
        if (top.object) {
          const [k, val] = top.items[top.idx] as readonly [string, JsonValue];
          writeString(out, k);
          out.byte(0x3a);
          v = val;
        } else {
          v = top.items[top.idx] as JsonValue;
        }
        break;
      }
      out.byte(top.object ? 0x7d : 0x5d);
      stack.pop();
    }
  }
}

function checkedRaw(raw: string): string {
  if (!NUMBER_RE.test(raw)) throw new JsonError(`invalid JSON number ${JSON.stringify(raw)}`);
  return raw;
}

/**
 * jsonwire.ReformatNumber with CanonicalizeNumbers: parse as float64, map
 * ±0 to 0 and ±Inf to ±MaxFloat64, then format as ES6 Number::toString
 * (which is what Go's AppendFloat reproduces).
 */
function canonicalNumber(raw: string): string {
  let f = parseNumber(raw);
  if (f === 0) return "0";
  if (f === Infinity) f = Number.MAX_VALUE;
  else if (f === -Infinity) f = -Number.MAX_VALUE;
  return String(f);
}

const HEX = "0123456789abcdef";

/** Writes a string with minimal escaping (RFC 8785 section 3.2.2.2; also Go's default encoder). */
function writeString(out: ByteWriter, s: string): void {
  out.byte(0x22);
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c < 0x80) {
      switch (c) {
        case 0x22:
          out.ascii('\\"');
          break;
        case 0x5c:
          out.ascii("\\\\");
          break;
        case 0x08:
          out.ascii("\\b");
          break;
        case 0x0c:
          out.ascii("\\f");
          break;
        case 0x0a:
          out.ascii("\\n");
          break;
        case 0x0d:
          out.ascii("\\r");
          break;
        case 0x09:
          out.ascii("\\t");
          break;
        default:
          if (c < 0x20) out.ascii(`\\u00${HEX[c >> 4]}${HEX[c & 0xf]}`);
          else out.byte(c);
      }
    } else if (c < 0x800) {
      out.byte(0xc0 | (c >> 6));
      out.byte(0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdfff) {
      const d = s.charCodeAt(k + 1);
      if (c > 0xdbff || !(d >= 0xdc00 && d <= 0xdfff)) throw new JsonError("invalid UTF-16 in string");
      const cp = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
      out.byte(0xf0 | (cp >> 18));
      out.byte(0x80 | ((cp >> 12) & 0x3f));
      out.byte(0x80 | ((cp >> 6) & 0x3f));
      out.byte(0x80 | (cp & 0x3f));
      k++;
    } else {
      out.byte(0xe0 | (c >> 12));
      out.byte(0x80 | ((c >> 6) & 0x3f));
      out.byte(0x80 | (c & 0x3f));
    }
  }
  out.byte(0x22);
}

class ByteWriter {
  private buf = new Uint8Array(256);
  private len = 0;

  byte(b: number): void {
    if (this.len === this.buf.length) {
      const next = new Uint8Array(this.buf.length * 2);
      next.set(this.buf);
      this.buf = next;
    }
    this.buf[this.len++] = b;
  }

  ascii(s: string): void {
    for (let k = 0; k < s.length; k++) this.byte(s.charCodeAt(k));
  }

  bytes(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}
