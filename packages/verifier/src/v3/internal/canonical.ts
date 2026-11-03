/** Binary field encodings of the attestation document, accepting exactly one encoding per byte string. */

const LOWER_HEX_RE = /^[0-9a-f]*$/;

/** Reports whether s contains only lowercase hex digits. Does not check length parity. */
export function isLowerHex(s: string): boolean {
  return LOWER_HEX_RE.test(s);
}

/** Decodes a required lowercase hex field of exactly `wantLen` bytes. */
export function decodeLowerHex(name: string, value: string, wantLen: number): Uint8Array {
  if (!isLowerHex(value)) {
    throw new Error(`${name} is not lowercase hex`);
  }
  if (value.length % 2 !== 0) {
    throw new Error(`${name} is not hex: encoding/hex: odd length hex string`);
  }
  const b = new Uint8Array(value.length / 2);
  for (let i = 0; i < b.length; i++) {
    b[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  if (b.length !== wantLen) {
    throw new Error(`${name} must be ${wantLen} bytes, got ${b.length}`);
  }
  return b;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_INDEX: Record<string, number> = Object.create(null) as Record<string, number>;
for (let i = 0; i < B64.length; i++) B64_INDEX[B64[i]!] = i;

/** Decodes a standard-base64 field, rejecting any non-canonical encoding (re-encode round trip). */
export function decodeBase64(name: string, value: string): Uint8Array {
  const b = strictDecode(value);
  if (b === undefined) {
    throw new Error(`decoding ${name}: illegal base64 data`);
  }
  if (encode(b) !== value) {
    throw new Error(`${name} is not canonical base64`);
  }
  return b;
}

/**
 * Strict standard base64: skips '\r' and '\n', requires padding to a
 * multiple of 4, and rejects non-zero padding bits. Returns undefined on any
 * other malformed input.
 */
function strictDecode(input: string): Uint8Array | undefined {
  const s = input.replace(/[\r\n]/g, "");
  if (s.length % 4 !== 0) return undefined;
  const out = new Uint8Array((s.length / 4) * 3);
  let n = 0;
  for (let q = 0; q < s.length; q += 4) {
    const last = q + 4 === s.length;
    let pad = 0;
    if (last && s[q + 3] === "=") pad = s[q + 2] === "=" ? 2 : 1;
    const v: number[] = [];
    for (let k = 0; k < 4 - pad; k++) {
      const d = B64_INDEX[s[q + k]!];
      if (d === undefined) return undefined;
      v.push(d);
    }
    const [a, b, c = 0, d = 0] = v as [number, number, number?, number?];
    const word = (a << 18) | (b << 12) | (c << 6) | d;
    // Strict: the bits dropped by padding must be zero.
    if (pad === 2 && (word & 0xffff) !== 0) return undefined;
    if (pad === 1 && (word & 0xff) !== 0) return undefined;
    out[n++] = word >> 16;
    if (pad < 2) out[n++] = (word >> 8) & 0xff;
    if (pad < 1) out[n++] = word & 0xff;
  }
  return out.slice(0, n);
}

/** base64.StdEncoding.EncodeToString. */
function encode(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 3) {
    const rem = b.length - i;
    const word = (b[i]! << 16) | ((rem > 1 ? b[i + 1]! : 0) << 8) | (rem > 2 ? b[i + 2]! : 0);
    s += B64[word >> 18]! + B64[(word >> 12) & 63]!;
    s += rem > 1 ? B64[(word >> 6) & 63]! : "=";
    s += rem > 2 ? B64[word & 63]! : "=";
  }
  return s;
}
