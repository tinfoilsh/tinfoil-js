// Byte-level primitives shared by the v3 verifier: strict lowercase-hex and
// canonical-base64 decoding (mirroring Go's encoding/hex, encoding/base64
// semantics), SHA-256, and UTF-8 helpers. All errors are plain Errors; the
// calling module assigns the rejection layer.

import { createHash } from "node:crypto";

const lowerHexRE = /^[0-9a-f]*$/;
const anyHexRE = /^[0-9a-fA-F]*$/;

export function isLowerHex(value: string): boolean {
  return lowerHexRE.test(value);
}

export function encodeHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

// decodeHex mirrors Go hex.DecodeString: either case, even length required.
export function decodeHex(value: string): Uint8Array {
  if (!anyHexRE.test(value) || value.length % 2 !== 0) {
    throw new Error("invalid hex string");
  }
  return new Uint8Array(Buffer.from(value, "hex"));
}

// decodeLowerHex decodes a required lowercase hex field of an exact byte length.
export function decodeLowerHex(name: string, value: string, wantLen: number): Uint8Array {
  if (!lowerHexRE.test(value)) {
    throw new Error(`${name} is not lowercase hex`);
  }
  if (value.length % 2 !== 0) {
    throw new Error(`${name} is not hex: odd length hex string`);
  }
  const b = new Uint8Array(Buffer.from(value, "hex"));
  if (b.length !== wantLen) {
    throw new Error(`${name} must be ${wantLen} bytes, got ${b.length}`);
  }
  return b;
}

export function encodeBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

const base64RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// decodeBase64 mirrors Go base64.StdEncoding.DecodeString: standard alphabet,
// padding required, \r and \n skipped, non-canonical padding bits tolerated.
export function decodeBase64(value: string): Uint8Array {
  const stripped = value.replace(/[\r\n]/g, "");
  if (!base64RE.test(stripped)) {
    throw new Error("invalid base64 string");
  }
  return new Uint8Array(Buffer.from(stripped, "base64"));
}

// decodeCanonicalBase64 decodes a required standard-base64 field and rejects
// non-canonical encodings: the round-trip comparison guarantees exactly one
// accepted encoding per byte string.
export function decodeCanonicalBase64(name: string, value: string): Uint8Array {
  if (!base64RE.test(value)) {
    throw new Error(`decoding ${name}: illegal base64 data`);
  }
  const b = new Uint8Array(Buffer.from(value, "base64"));
  if (Buffer.from(b).toString("base64") !== value) {
    throw new Error(`${name} is not canonical base64`);
  }
  return b;
}

export function sha256(...chunks: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const c of chunks) h.update(c);
  return new Uint8Array(h.digest());
}

export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// utf8Decode rejects invalid UTF-8 (Go: utf8.Valid before parsing).
export function utf8Decode(b: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b);
  } catch {
    throw new Error("input is not valid UTF-8");
  }
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
