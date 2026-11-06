/**
 * Strict JSON: parsing that rejects what lenient parsers accept, and
 * serialization in canonical and compact forms.
 *
 * - invalid UTF-8 rejects, as does a leading byte-order mark;
 * - escaped surrogates must form a valid pair (`"\ud800"` rejects);
 * - duplicate member names reject at any depth, compared on decoded names;
 * - trailing data after the top-level value rejects;
 * - nesting deeper than 10000 levels rejects;
 * - numbers keep their source literal so u64 fields survive above 2^53;
 * - objects remember their source text, so a decoder can hand a member on
 *   as the exact text it was sent as (see {@link sourceText}).
 *
 * Parsing is JSON.parse plus checks: TextDecoder handles UTF-8, a scan over
 * the validated text rejects duplicates and keeps member order, number
 * literals and object spans, and a final walk rejects lone surrogates.
 * Unknown-member rejection depends on the member set each decoder expects, so
 * it lives in the decoders (see decode.ts), not here.
 */

/** A parsed JSON value. Objects are Maps so member names can't collide with Object.prototype. */
export type JsonValue = null | boolean | JsonNumber | string | readonly JsonValue[] | JsonObject;
export type JsonObject = ReadonlyMap<string, JsonValue>;

/** RFC 8259 number grammar. */
const NUMBER_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/;
/** An optional '-' then digits with no leading zero: the only literals integer fields accept. */
const INTEGER_RE = /^-?(?:0|[1-9][0-9]*)$/;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** A JSON number, kept as its source literal. */
export class JsonNumber {
  constructor(readonly raw: string) {}

  /**
   * The number as an integer, if the literal is one (no fraction or exponent) within ±(2^53-1).
   * "1.0" and "1e2" are not integers; "-0" is 0.
   */
  toSafeInteger(): number {
    const n = this.toBigInt();
    if (n > MAX_SAFE || n < -MAX_SAFE) {
      throw new JsonError(`JSON number ${this.raw} is out of range`);
    }
    return Number(n);
  }

  /**
   * The number as an integer of any size, if the literal is one. "-0" yields 0n,
   * so unsigned fields, which reject any leading '-', must check `raw` for a
   * sign as well as range-checking the result.
   */
  toBigInt(): bigint {
    if (!INTEGER_RE.test(this.raw)) {
      throw new JsonError(`JSON number ${this.raw} is not an integer`);
    }
    return BigInt(this.raw);
  }

  /**
   * The literal's float64 value: correctly rounded, underflow to ±0 is fine,
   * overflow to ±Inf is an error. Used by the provenance layer's protobuf
   * round-trip of the platform predicate.
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

/** The deepest container nesting parse and write accept. */
const MAX_DEPTH = 10000;

/** Parses exactly one JSON value from UTF-8 bytes. Throws JsonError. */
export function strictParse(bytes: Uint8Array): JsonValue {
  let text: string;
  try {
    // fatal: invalid UTF-8 rejects. ignoreBOM: a leading BOM stays in the
    // text, where JSON.parse rejects it.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new JsonError("invalid UTF-8");
  }

  let parsed: unknown;
  try {
    // JSON.parse enforces the RFC 8259 grammar and rejects trailing data.
    // Without a reviver it is iterative, so depth is bounded only by scan().
    parsed = JSON.parse(text);
  } catch (err) {
    throw new JsonError(`invalid JSON: ${(err as Error).message}`);
  }

  return toJsonValue(parsed, scan(text));
}

/**
 * The source text of an object {@link strictParse} produced: the span from
 * its opening to its closing brace, byte for byte as parsed, since the text
 * is a lossless decoding of valid UTF-8. Undefined for any other Map, such
 * as a copy from {@link cloneJsonValue} or one built by hand.
 */
export function sourceText(o: JsonObject): string | undefined {
  const span = sources.get(o);
  return span === undefined ? undefined : span.text.slice(span.start, span.end);
}

/** Each parsed object's span in its source text, released with the object. */
const sources = new WeakMap<JsonObject, { readonly text: string; readonly start: number; readonly end: number }>();

/** What scan() recovers from the text that JSON.parse's output lacks. */
interface Scan {
  readonly text: string;
  /** Each object in document order: its member names in source order and its span in `text`. */
  readonly objects: readonly ObjectScan[];
  /** Every number literal, in document order. */
  readonly numbers: readonly string[];
}

interface ObjectScan {
  readonly order: string[];
  readonly start: number;
  /** The index after the closing brace. */
  end: number;
}

/**
 * Scans text JSON.parse has already validated for what its output lacks:
 * rejects duplicate member names (compared after unescaping) and nesting
 * deeper than MAX_DEPTH, and records each object's member names in source
 * order and span, and every number's source literal (so integers beyond
 * 2^53 and "1" vs "1.0" stay distinguishable). Because the grammar is
 * already checked, this only tracks nesting, decodes each string followed
 * by ':' (a member name), and copies number tokens.
 */
function scan(text: string): Scan {
  const objects: ObjectScan[] = [];
  const numbers: string[] = [];
  const stack: ({ readonly seen: Set<string>; readonly object: ObjectScan } | null)[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x7b /* { */ || c === 0x5b /* [ */) {
      if (stack.length >= MAX_DEPTH) throw new JsonError("exceeded max depth");
      if (c === 0x7b) {
        const object: ObjectScan = { order: [], start: i, end: -1 };
        objects.push(object);
        stack.push({ seen: new Set(), object });
      } else {
        stack.push(null);
      }
    } else if (c === 0x7d /* } */ || c === 0x5d /* ] */) {
      const top = stack.pop();
      if (top) top.object.end = i + 1;
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
        top.object.order.push(name);
      }
    } else if (c === 0x2d /* - */ || (c >= 0x30 && c <= 0x39)) {
      // A number token; valid JSON puts digits only inside strings or numbers.
      const start = i;
      while (i + 1 < text.length && /[-+.0-9eE]/.test(text[i + 1]!)) i++;
      numbers.push(text.slice(start, i + 1));
    }
  }
  return { text, objects, numbers };
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function checkString(s: string): string {
  // Valid UTF-8 can't encode a surrogate, so a lone one came from an escape
  // such as "\ud800", which is invalid.
  if (LONE_SURROGATE.test(s)) throw new JsonError("invalid escaped surrogate in string");
  return s;
}

/**
 * Converts JSON.parse output to JsonValue without recursion: objects become
 * Maps (so names can't collide with Object.prototype) in source member order
 * and remember their source span, numbers become JsonNumbers holding their
 * source literal (both consumed from the scan in document order, which is
 * the order this walk visits values), and every string and member name is
 * checked for lone surrogates.
 */
function toJsonValue(root: unknown, { text, objects, numbers }: Scan): JsonValue {
  let nextObject = 0;
  let nextNumber = 0;
  type Frame = { readonly src: Record<string, unknown> | unknown[]; readonly keys: string[]; idx: number; readonly out: Map<string, JsonValue> | JsonValue[] };
  const convert = (v: unknown): JsonValue | Frame => {
    if (v === null || typeof v === "boolean") return v;
    if (typeof v === "string") return checkString(v);
    if (typeof v === "number") {
      const raw = numbers[nextNumber++];
      if (raw === undefined || Number(raw) !== v) throw new JsonError("number scan disagrees with JSON.parse");
      return new JsonNumber(raw);
    }
    if (Array.isArray(v)) return { src: v, keys: [], idx: 0, out: [] };
    const o = v as Record<string, unknown>;
    const scanned = objects[nextObject++];
    if (scanned === undefined || scanned.order.length !== Object.keys(o).length) {
      throw new JsonError("member scan disagrees with JSON.parse");
    }
    const out = new Map<string, JsonValue>();
    sources.set(out, { text, start: scanned.start, end: scanned.end });
    return { src: o, keys: scanned.order.map(checkString), idx: 0, out };
  };
  const finish = (v: JsonValue): JsonValue => {
    if (nextNumber !== numbers.length || nextObject !== objects.length) {
      throw new JsonError("scan disagrees with JSON.parse");
    }
    return v;
  };
  const isFrame = (x: JsonValue | Frame): x is Frame =>
    typeof x === "object" && x !== null && !(x instanceof JsonNumber) && !(x instanceof Map) && !Array.isArray(x);

  const first = convert(root);
  if (!isFrame(first)) return finish(first);
  const stack: Frame[] = [first];
  for (;;) {
    const f = stack[stack.length - 1]!;
    const arr = Array.isArray(f.src);
    const len = arr ? (f.src as unknown[]).length : f.keys.length;
    if (f.idx === len) {
      stack.pop();
      const done = f.out as JsonValue;
      if (stack.length === 0) return finish(done);
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

/** Parses a JSON number literal as float64 (round-to-nearest-even). */
function parseNumber(raw: string): number {
  if (!NUMBER_RE.test(raw)) throw new JsonError(`invalid JSON number ${JSON.stringify(raw)}`);
  return Number(raw);
}

/** Serializes a value in RFC 8785 canonical form: sorted members, minimal escaping, ES6 number formatting. */
export function canonicalize(value: JsonValue): Uint8Array {
  return write(value, true);
}

/**
 * Serializes a value compactly, preserving member order and number literals.
 * Used by the provenance layer to hand bundles and statements to the Sigstore
 * library as bytes.
 */
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
 * Number canonicalization: parse as float64, map ±0 to 0, then format as ES6
 * Number::toString (the RFC 8785 form). A literal that overflows float64 is
 * written as ±MAX_VALUE rather than rejected, so any number literal strict
 * parsing accepted can be canonicalized.
 */
function canonicalNumber(raw: string): string {
  let f = parseNumber(raw);
  if (f === 0) return "0";
  if (f === Infinity) f = Number.MAX_VALUE;
  else if (f === -Infinity) f = -Number.MAX_VALUE;
  return String(f);
}

const HEX = "0123456789abcdef";

/** Writes a string with minimal escaping (RFC 8785 section 3.2.2.2). */
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

/** A deep copy of a value, sharing no Maps or arrays with the original. */
export function cloneJsonValue(root: JsonValue): JsonValue {
  type Frame = { readonly src: readonly JsonValue[] | ReadonlyArray<readonly [string, JsonValue]>; idx: number; readonly out: JsonValue[] | Map<string, JsonValue> };
  const frame = (v: JsonValue): Frame | undefined => {
    if (Array.isArray(v)) return { src: v, idx: 0, out: [] };
    if (v instanceof Map) return { src: [...v], idx: 0, out: new Map() };
    return undefined;
  };
  const first = frame(root);
  if (first === undefined) return root;
  const stack: Frame[] = [first];
  for (;;) {
    const f = stack[stack.length - 1]!;
    if (f.idx === f.src.length) {
      stack.pop();
      if (stack.length === 0) return f.out;
      place(stack[stack.length - 1]!, f.out);
      continue;
    }
    const entry = f.src[f.idx]!;
    const child: JsonValue = f.out instanceof Map ? (entry as readonly [string, JsonValue])[1] : (entry as JsonValue);
    const sub = frame(child);
    if (sub !== undefined) stack.push(sub);
    else place(f, child);
  }

  function place(f: Frame, v: JsonValue): void {
    if (f.out instanceof Map) f.out.set((f.src[f.idx] as readonly [string, JsonValue])[0], v);
    else f.out.push(v);
    f.idx++;
  }
}
