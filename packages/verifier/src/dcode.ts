/**
 * Decode dcode-encoded data from certificate SANs.
 * Format: NN<base32-chunk>.<prefix>.<domain> where NN is chunk index.
 */

import { AttestationError } from './errors.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input: string): Uint8Array {
  const s = input.toUpperCase().replace(/=+$/, '');
  if (!s) return new Uint8Array(0);
  
  const out = new Uint8Array(Math.floor(s.length * 5 / 8));
  let bits = 0, val = 0, idx = 0;
  
  for (const c of s) {
    const i = B32.indexOf(c);
    if (i < 0) throw new AttestationError(`Invalid base32: ${c}`);
    val = (val << 5) | i;
    if ((bits += 5) >= 8) out[idx++] = (val >> (bits -= 8)) & 0xff;
  }
  return out;
}

export function decodeDomains(domains: string[], prefix: string): Uint8Array {
  const pattern = `.${prefix}.`;
  const chunks = domains
    .filter(d => d.includes(pattern))
    .sort((a, b) => +a.slice(0, 2) - +b.slice(0, 2))
    .map(d => d.split('.')[0].slice(2))
    .join('');
  
  if (!chunks) throw new AttestationError(`No domains with prefix: ${prefix}`);
  return base32Decode(chunks);
}

export const bytesToHex = (b: Uint8Array) => 
  [...b].map(x => x.toString(16).padStart(2, '0')).join('');
