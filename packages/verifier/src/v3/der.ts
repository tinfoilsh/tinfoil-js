// Shared minimal strict-DER reader used by the SEV (sev/x509.ts) and TDX
// (tdx/der.ts) X.509 parsers. Engine-neutral (WebCrypto/browser safe). All
// errors are plain Errors; callers assign the rejection layer.

import { bytesToLatin1, decodeBase64, encodeHex } from "./bytes.js";

// ASN.1 tag numbers (universal class).
export const tagBoolean = 0x01;
export const tagInteger = 0x02;
export const tagBitString = 0x03;
export const tagOctetString = 0x04;
export const tagOID = 0x06;
export const tagUTF8String = 0x0c;
export const tagSequence = 0x10;
export const tagSet = 0x11;
export const tagPrintableString = 0x13;
export const tagIA5String = 0x16;
export const tagUTCTime = 0x17;
export const tagGeneralizedTime = 0x18;

export interface TLV {
  cls: number; // 0 universal, 2 context
  constructed: boolean;
  tag: number;
  start: number; // offset of the tag byte
  contentStart: number;
  end: number; // one past the last content byte
}

export function readTLV(b: Uint8Array, off: number): TLV {
  if (off + 2 > b.length) throw new Error("truncated DER element");
  const first = b[off];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  const tag = first & 0x1f;
  if (tag === 0x1f) throw new Error("multi-byte DER tags are not supported");
  let len = b[off + 1];
  let contentStart = off + 2;
  if (len === 0x80) throw new Error("indefinite DER length");
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4 || off + 2 + n > b.length) throw new Error("invalid DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i];
    contentStart = off + 2 + n;
  }
  const end = contentStart + len;
  if (end > b.length) throw new Error("DER element overruns input");
  return { cls, constructed, tag, start: off, contentStart, end };
}

export function content(b: Uint8Array, t: TLV): Uint8Array {
  return b.subarray(t.contentStart, t.end);
}

export function rawOf(b: Uint8Array, t: TLV): Uint8Array {
  return b.subarray(t.start, t.end);
}

export function expectTag(b: Uint8Array, off: number, tag: number, what: string): TLV {
  const t = readTLV(b, off);
  if (t.cls !== 0 || t.tag !== tag) {
    throw new Error(`expected ${what}, found tag ${t.cls}/${t.tag}`);
  }
  return t;
}

// children splits a constructed element's content into its child TLVs.
export function children(b: Uint8Array, t: TLV): TLV[] {
  const out: TLV[] = [];
  let off = t.contentStart;
  while (off < t.end) {
    const c = readTLV(b, off);
    out.push(c);
    off = c.end;
  }
  return out;
}

export function decodeOID(b: Uint8Array): string {
  if (b.length === 0) throw new Error("empty OID");
  const parts: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

// decodeUint parses a DER INTEGER content as an unsigned number (throws on
// negative or oversized values), mirroring Go's asn1 int64 decoding limits.
export function decodeUint(b: Uint8Array, what: string): number {
  if (b.length === 0) throw new Error(`${what}: empty integer`);
  if ((b[0] & 0x80) !== 0) throw new Error(`${what}: negative integer`);
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  if (b.length - start > 6) throw new Error(`${what}: integer too large`);
  let v = 0;
  for (let i = start; i < b.length; i++) v = v * 256 + b[i];
  return v;
}

// serialHexFromInteger normalizes an INTEGER's content to lowercase hex with
// leading zeros stripped, so serial comparison matches Go's big.Int.Cmp.
export function serialHexFromInteger(b: Uint8Array): string {
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  return encodeHex(b.subarray(start));
}

export function parseTime(b: Uint8Array, t: TLV): Date {
  const s = bytesToLatin1(content(b, t));
  let iso: string;
  if (t.tag === tagUTCTime) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error(`invalid UTCTime ${JSON.stringify(s)}`);
    const yy = parseInt(m[1], 10);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    iso = `${year}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  } else if (t.tag === tagGeneralizedTime) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error(`invalid GeneralizedTime ${JSON.stringify(s)}`);
    iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  } else {
    throw new Error("expected UTCTime or GeneralizedTime");
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) throw new Error(`invalid time ${JSON.stringify(s)}`);
  return d;
}

export interface Extension {
  oid: string;
  critical: boolean;
  value: Uint8Array; // extnValue OCTET STRING contents
}

export function parseExtensions(b: Uint8Array, extSeq: TLV): Extension[] {
  const out: Extension[] = [];
  for (const ext of children(b, extSeq)) {
    const parts = children(b, ext);
    if (parts.length < 2 || parts.length > 3 || parts[0].tag !== tagOID) {
      throw new Error("malformed X.509 extension");
    }
    const oid = decodeOID(content(b, parts[0]));
    let critical = false;
    let valueIdx = 1;
    if (parts.length === 3) {
      if (parts[1].tag !== tagBoolean) throw new Error("malformed X.509 extension critical flag");
      critical = content(b, parts[1])[0] !== 0;
      valueIdx = 2;
    }
    if (parts[valueIdx].tag !== tagOctetString) throw new Error("extension value is not an OCTET STRING");
    out.push({ oid, critical, value: content(b, parts[valueIdx]) });
  }
  return out;
}

export function bitStringBytes(b: Uint8Array, t: TLV, what: string): Uint8Array {
  const c = content(b, t);
  if (c.length === 0 || c[0] !== 0) throw new Error(`${what}: unsupported BIT STRING padding`);
  return c.subarray(1);
}

// PEM handling (Go encoding/pem.Decode subset: first block + rest).

export interface PEMBlock {
  type: string;
  der: Uint8Array;
  rest: string;
}

const pemRE = /-----BEGIN ([^-]+)-----\r?\n([A-Za-z0-9+/=\r\n]*)-----END \1-----(?:\r?\n)?/;

export function pemDecode(text: string): PEMBlock | undefined {
  const m = pemRE.exec(text);
  if (!m) return undefined;
  const b64 = m[2].replace(/[\r\n]/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64)) return undefined;
  return {
    type: m[1],
    der: decodeBase64(b64),
    rest: text.slice((m.index ?? 0) + m[0].length),
  };
}

export function derBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
