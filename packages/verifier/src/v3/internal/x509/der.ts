/**
 * Strict DER: definite lengths in minimal form, minimal integers, BOOLEAN
 * as 0x00 or 0xFF, and UTCTime/GeneralizedTime with a trailing 'Z'. Anything
 * BER-only is rejected, so two encodings of one value can't both verify.
 *
 * The ASN.1 tokenizer from `@freedomofpress/crypto-browser` splits the bytes
 * into a tree and checks that nested lengths add up. It accepts a number of
 * BER encodings, so `decode` walks the raw bytes alongside its tree and
 * rejects every one of them: a length that fits a shorter form, an INTEGER
 * with a redundant sign byte, a BOOLEAN other than 0x00/0xFF, a constructed
 * string, an unused-bit count with set bits, a time with fractional seconds
 * or a missing 'Z', and any bytes after the top-level element.
 */
import { ASN1Obj } from "@freedomofpress/crypto-browser";

/** A decoded TLV. `value` is the content bytes; `raw` the whole element. */
export interface DerElement {
  readonly tagClass: number;
  readonly constructed: boolean;
  readonly tag: number;
  readonly value: Uint8Array;
  readonly raw: Uint8Array;
}

/** Thrown for any DER violation. */
export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerError";
  }
}

/** Universal tag numbers this module interprets. */
export const TAG = {
  BOOLEAN: 1,
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  ENUMERATED: 10,
  UTF8_STRING: 12,
  SEQUENCE: 16,
  SET: 17,
  PRINTABLE_STRING: 19,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
} as const;

export const CLASS_UNIVERSAL = 0;
export const CLASS_CONTEXT = 2;

/** The decoded children of every constructed element `decode` has produced. */
const childrenOf = new WeakMap<DerElement, DerElement[]>();

interface Header {
  readonly tagClass: number;
  readonly constructed: boolean;
  readonly tag: number;
  /** Bytes taken by the tag and length octets. */
  readonly headerLength: number;
  /** Content length. */
  readonly length: number;
}

/** Reads the tag and length octets at `offset`, requiring the minimal definite length form. */
function readHeader(bytes: Uint8Array, offset: number): Header {
  if (bytes.length - offset < 2) throw new DerError("truncated element header");
  const t = bytes[offset];
  const tag = t & 0x1f;
  if (tag === 0x1f) throw new DerError("long-form tag numbers are not supported");
  const first = bytes[offset + 1];
  if (first < 0x80) {
    return { tagClass: t >> 6, constructed: (t & 0x20) !== 0, tag, headerLength: 2, length: first };
  }
  if (first === 0x80) throw new DerError("indefinite length is not DER");
  const count = first & 0x7f;
  if (count > 4) throw new DerError("length octets exceed the supported range");
  if (bytes.length - offset < 2 + count) throw new DerError("truncated length");
  let length = 0;
  for (let i = 0; i < count; i++) length = length * 256 + bytes[offset + 2 + i];
  // Minimal form: no leading zero length byte, and the long form only when the
  // value does not fit the short form.
  if (bytes[offset + 2] === 0 || length < 0x80) throw new DerError("length is not in minimal form");
  return { tagClass: t >> 6, constructed: (t & 0x20) !== 0, tag, headerLength: 2 + count, length };
}

/** Universal tags that DER encodes only as primitives (everything except SEQUENCE and SET). */
function mustBePrimitive(tag: number): boolean {
  return tag !== TAG.SEQUENCE && tag !== TAG.SET;
}

function checkInteger(value: Uint8Array): void {
  if (value.length === 0) throw new DerError("INTEGER has no content");
  if (value.length >= 2) {
    const redundantZero = value[0] === 0x00 && (value[1] & 0x80) === 0;
    const redundantOnes = value[0] === 0xff && (value[1] & 0x80) !== 0;
    if (redundantZero || redundantOnes) throw new DerError("INTEGER is not minimally encoded");
  }
}

function checkBoolean(value: Uint8Array): void {
  if (value.length !== 1 || (value[0] !== 0x00 && value[0] !== 0xff)) {
    throw new DerError("BOOLEAN must be a single 0x00 or 0xFF byte");
  }
}

function checkBitString(value: Uint8Array): void {
  if (value.length === 0) throw new DerError("BIT STRING has no unused-bits octet");
  const unused = value[0];
  if (unused > 7) throw new DerError("BIT STRING unused-bits count exceeds 7");
  if (value.length === 1 && unused !== 0) throw new DerError("empty BIT STRING with unused bits");
  if (unused > 0 && (value[value.length - 1] & ((1 << unused) - 1)) !== 0) {
    throw new DerError("BIT STRING unused bits must be zero");
  }
}

function checkOid(value: Uint8Array): void {
  if (value.length === 0) throw new DerError("OBJECT IDENTIFIER has no content");
  if ((value[value.length - 1] & 0x80) !== 0) throw new DerError("OBJECT IDENTIFIER is truncated");
  let start = true;
  for (const b of value) {
    if (start && b === 0x80) throw new DerError("OBJECT IDENTIFIER sub-identifier is not minimally encoded");
    start = (b & 0x80) === 0;
  }
}

const UTC_TIME_RE = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
// GeneralizedTime may carry fractional seconds; DER requires the fraction to
// omit trailing zeros, so a fraction is never empty and never ends in '0'.
const GENERALIZED_TIME_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/;

function ascii(value: Uint8Array): string {
  let s = "";
  for (const b of value) {
    if (b < 0x20 || b > 0x7e) throw new DerError("time contains a non-printable byte");
    s += String.fromCharCode(b);
  }
  return s;
}

/**
 * Parses a time value: the 'Z' suffix, a real calendar date, and whole
 * seconds unless `fractionalSeconds` admits a DER fraction on a
 * GeneralizedTime (kept to millisecond precision).
 */
function parseTime(tag: number, value: Uint8Array, fractionalSeconds: boolean): Date {
  const text = ascii(value);
  const m = tag === TAG.UTC_TIME ? UTC_TIME_RE.exec(text) : GENERALIZED_TIME_RE.exec(text);
  if (!m) throw new DerError("time must be UTC with a 'Z' suffix");
  const fraction = m[7];
  if (fraction !== undefined) {
    if (!fractionalSeconds) throw new DerError("time must be whole seconds");
    if (fraction.endsWith("0")) throw new DerError("fractional seconds must omit trailing zeros");
  }
  let year = Number(m[1]);
  if (tag === TAG.UTC_TIME) year += year >= 50 ? 1900 : 2000;
  const [month, day, hour, minute, second] = [m[2], m[3], m[4], m[5], m[6]].map(Number);
  const millis = fraction === undefined ? 0 : Number(`${fraction}00`.slice(0, 3));
  const ms = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  const d = new Date(ms);
  // Date.UTC rolls over out-of-range fields; a valid date reads back unchanged.
  if (
    d.getUTCFullYear() !== year ||
    d.getUTCMonth() !== month - 1 ||
    d.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    throw new DerError("time is not a valid calendar date");
  }
  return d;
}

/**
 * Content checks for universal primitives. A primitive of another class is an
 * implicitly tagged value whose underlying type only its schema knows, so it
 * is left to the consumer.
 */
function checkPrimitive(h: Header, value: Uint8Array): void {
  if (h.tagClass !== CLASS_UNIVERSAL) return;
  switch (h.tag) {
    case TAG.BOOLEAN:
      checkBoolean(value);
      break;
    case TAG.INTEGER:
    case TAG.ENUMERATED:
      checkInteger(value);
      break;
    case TAG.BIT_STRING:
      checkBitString(value);
      break;
    case TAG.NULL:
      if (value.length !== 0) throw new DerError("NULL must be empty");
      break;
    case TAG.OID:
      checkOid(value);
      break;
    case TAG.UTC_TIME:
    case TAG.GENERALIZED_TIME:
      parseTime(h.tag, value, true);
      break;
    default:
      break;
  }
}

/**
 * Audits the element at `offset` against the tokenizer's view of it, building
 * the DerElement tree. Returns the offset just past the element.
 */
function audit(bytes: Uint8Array, offset: number, obj: ASN1Obj): { element: DerElement; end: number } {
  const h = readHeader(bytes, offset);
  const contentStart = offset + h.headerLength;
  const end = contentStart + h.length;
  if (end > bytes.length) throw new DerError("element extends past the end of its container");
  if (h.tag !== obj.tag.number || h.length !== obj.value.length) {
    throw new DerError("element does not match its tokenized form");
  }
  if (h.tagClass === CLASS_UNIVERSAL) {
    if (h.constructed && mustBePrimitive(h.tag)) throw new DerError("constructed encoding of a primitive type");
    if (!h.constructed && !mustBePrimitive(h.tag)) throw new DerError("SEQUENCE and SET must be constructed");
  }
  const element: DerElement = {
    tagClass: h.tagClass,
    constructed: h.constructed,
    tag: h.tag,
    value: bytes.subarray(contentStart, end),
    raw: bytes.subarray(offset, end),
  };
  if (h.constructed) {
    const kids: DerElement[] = [];
    let pos = contentStart;
    for (const sub of obj.subs) {
      const r = audit(bytes, pos, sub);
      kids.push(r.element);
      pos = r.end;
    }
    if (pos !== end) throw new DerError("constructed element's children do not fill its length");
    childrenOf.set(element, kids);
  } else {
    checkPrimitive(h, element.value);
  }
  return { element, end };
}

/** Runs the tokenizer, converting its failures into DerError. */
function tokenize(bytes: Uint8Array): ASN1Obj {
  try {
    return ASN1Obj.parseBuffer(bytes);
  } catch (e) {
    throw new DerError(`malformed DER: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** Decodes exactly one element from `bytes`; trailing bytes reject. */
export function decode(bytes: Uint8Array): DerElement {
  if (bytes.length === 0) throw new DerError("empty input");
  const { element, end } = audit(bytes, 0, tokenize(bytes));
  if (end !== bytes.length) throw new DerError("trailing bytes after the element");
  return element;
}

/** Decodes the elements of a SEQUENCE or SET's content, in order. */
export function children(e: DerElement): DerElement[] {
  if (!e.constructed) throw new DerError("primitive element has no children");
  const known = childrenOf.get(e);
  if (known) return known.slice();
  return children(decode(e.raw));
}

function expectUniversal(e: DerElement, tag: number, name: string): void {
  if (e.tagClass !== CLASS_UNIVERSAL || e.tag !== tag || e.constructed) {
    throw new DerError(`expected ${name}`);
  }
}

/** A non-negative INTEGER as bigint; non-minimal encodings reject. */
export function integer(e: DerElement): bigint {
  expectUniversal(e, TAG.INTEGER, "INTEGER");
  checkInteger(e.value);
  if ((e.value[0] & 0x80) !== 0) throw new DerError("INTEGER is negative");
  let n = 0n;
  for (const b of e.value) n = (n << 8n) | BigInt(b);
  return n;
}

/** An OBJECT IDENTIFIER in dotted form. */
export function oid(e: DerElement): string {
  expectUniversal(e, TAG.OID, "OBJECT IDENTIFIER");
  checkOid(e.value);
  const arcs: bigint[] = [];
  let acc = 0n;
  for (const b of e.value) {
    acc = (acc << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(acc);
      acc = 0n;
    }
  }
  const first = arcs[0];
  const lead = first < 80n ? [first / 40n, first % 40n] : [2n, first - 80n];
  return [...lead, ...arcs.slice(1)].join(".");
}

/**
 * A UTCTime or GeneralizedTime; both require the 'Z' suffix. Whole seconds
 * only, unless `fractionalSeconds` admits a GeneralizedTime fraction.
 */
export function time(e: DerElement, options: { fractionalSeconds?: boolean } = {}): Date {
  if (e.tagClass !== CLASS_UNIVERSAL || e.constructed || (e.tag !== TAG.UTC_TIME && e.tag !== TAG.GENERALIZED_TIME)) {
    throw new DerError("expected UTCTime or GeneralizedTime");
  }
  return parseTime(e.tag, e.value, options.fractionalSeconds === true);
}

/** A BIT STRING's bytes; the unused-bits count must be 0. */
export function bitString(e: DerElement): Uint8Array {
  expectUniversal(e, TAG.BIT_STRING, "BIT STRING");
  checkBitString(e.value);
  if (e.value[0] !== 0) throw new DerError("BIT STRING must have no unused bits here");
  return e.value.subarray(1);
}

export function boolean(e: DerElement): boolean {
  expectUniversal(e, TAG.BOOLEAN, "BOOLEAN");
  checkBoolean(e.value);
  return e.value[0] === 0xff;
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Strict base64: canonical alphabet, correct padding, no stray characters. */
function base64Decode(text: string): Uint8Array {
  if (text.length % 4 !== 0) throw new DerError("PEM body is not a multiple of 4 base64 characters");
  const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((text.length / 4) * 3 - padding);
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    let bits = 0;
    for (let j = 0; j < 4; j++) {
      const c = text[i + j];
      const last = i + 4 === text.length;
      if (c === "=") {
        if (!last || j < 4 - padding) throw new DerError("PEM body has misplaced padding");
        bits <<= 6;
        continue;
      }
      const v = BASE64_ALPHABET.indexOf(c);
      if (v < 0) throw new DerError("PEM body contains a non-base64 character");
      bits = (bits << 6) | v;
    }
    const n = i + 4 === text.length ? 3 - padding : 3;
    for (let k = 0; k < n; k++) out[o++] = (bits >> (16 - 8 * k)) & 0xff;
  }
  return out;
}

/** Splits a PEM file into the DER bodies of its blocks of the given label, in order. */
export function pemBlocks(pem: string, label: string): Uint8Array[] {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  const out: Uint8Array[] = [];
  const lines = pem.split(/\r?\n/);
  let body: string[] | undefined;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (body === undefined) {
      // Blocks of other labels, and anything between blocks, are skipped.
      if (line === begin) body = [];
      continue;
    }
    if (line === end) {
      const text = body.join("");
      if (text.length === 0) throw new DerError(`empty ${label} block`);
      out.push(base64Decode(text));
      body = undefined;
    } else if (line.startsWith("-----")) {
      throw new DerError(`unexpected boundary inside ${label} block`);
    } else if (line.length > 0) {
      body.push(line);
    }
  }
  if (body !== undefined) throw new DerError(`unterminated ${label} block`);
  return out;
}

/** Converts an ECDSA signature from DER (SEQUENCE of two minimal INTEGERs) to fixed-width r‖s. */
export function ecdsaSignatureToRaw(der: Uint8Array, coordinateBytes: number): Uint8Array {
  const seq = decode(der);
  if (seq.tagClass !== CLASS_UNIVERSAL || seq.tag !== TAG.SEQUENCE) throw new DerError("ECDSA signature must be a SEQUENCE");
  const parts = children(seq);
  if (parts.length !== 2) throw new DerError("ECDSA signature must hold exactly r and s");
  const out = new Uint8Array(2 * coordinateBytes);
  parts.forEach((p, i) => {
    const n = integer(p);
    if (n === 0n) throw new DerError("ECDSA signature component is zero");
    const magnitude = p.value[0] === 0 ? p.value.subarray(1) : p.value;
    if (magnitude.length > coordinateBytes) throw new DerError("ECDSA signature component exceeds the coordinate size");
    out.set(magnitude, (i + 1) * coordinateBytes - magnitude.length);
  });
  return out;
}
