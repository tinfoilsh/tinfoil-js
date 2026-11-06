/** Small byte helpers shared across the verifier. WebCrypto only; no node: imports. */

/** `b` as lowercase hex, two digits per byte. */
export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/**
 * The bytes that `s` spells in lowercase hex: the form {@link toHex}
 * writes. Only lowercase digits of even length are accepted; anything else
 * throws a plain `Error`.
 */
export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) throw new Error(`not lowercase hex of even length: ${JSON.stringify(s)}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
}
