import { hex, requireThat, zero } from '../quote/crypto.js';

export class TDXQuote {
  readonly bytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly attestationKey: Uint8Array;
  readonly qeReport: Uint8Array;
  readonly qeSignature: Uint8Array;
  readonly authData: Uint8Array;
  readonly certificateChain: string;
  constructor(input: Uint8Array) {
    this.bytes = Uint8Array.from(input);
    requireThat(this.bytes.length >= 0x27c, 'truncated TDX quote');
    const view = new DataView(this.bytes.buffer);
    requireThat(view.getUint16(0, true) === 4 && view.getUint16(2, true) === 2 && view.getUint32(4, true) === 0x81, 'unsupported TDX quote header');
    requireThat(zero(this.bytes.slice(8, 12)), 'nonzero TDX quote header reserved bytes');
    requireThat(hex(this.bytes.slice(12, 28)) === '939a7233f79c4ca9940a0db3957f0607', 'TDX quote has non-Intel QE vendor');
    const end = 0x27c + view.getUint32(0x278, true);
    requireThat(end <= this.bytes.length && zero(this.bytes.slice(end)), 'truncated TDX signature data or nonzero unsigned trailing data');
    let pos = 0x27c;
    const read = (n: number): Uint8Array => { requireThat(pos + n <= end, 'truncated TDX certification data'); const b = this.bytes.slice(pos, pos + n); pos += n; return b; };
    const u16 = () => { const b = read(2); return new DataView(b.buffer).getUint16(0, true); };
    const u32 = () => { const b = read(4); return new DataView(b.buffer).getUint32(0, true); };
    this.signature = read(64); this.attestationKey = read(64);
    requireThat(u16() === 6, 'TDX quote requires QE report certification data');
    requireThat(u32() === end - pos, 'TDX QE certification data size mismatch');
    this.qeReport = read(384); this.qeSignature = read(64);
    this.authData = read(u16());
    requireThat(u16() === 5, 'TDX quote requires a PCK certificate chain');
    const chain = read(u32());
    requireThat(pos === end, 'TDX PCK certification data size mismatch');
    const chainBytes = chain[chain.length - 1] === 0 ? chain.slice(0, -1) : chain;
    this.certificateChain = new TextDecoder('utf-8', { fatal: true }).decode(chainBytes);
    for (const [start, end] of [[0x14, 0x30], [0x60, 0x80], [0xa0, 0x100], [0x104, 0x140]]) requireThat(zero(this.qeReport.slice(start, end)), 'nonzero QE report reserved bytes');
  }
  // Body offsets are relative to the 48-byte quote header.
  field(offset: number, size: number): Uint8Array { return this.bytes.slice(48 + offset, 48 + offset + size); }
  get mrtd(): string { return hex(this.field(0x88, 48)); }
  get rtmrs(): string[] { return [0, 1, 2, 3].map(i => hex(this.field(0x148 + i * 48, 48))); }
  get teeTCBSVN(): Uint8Array { return this.field(0, 16); }
}
