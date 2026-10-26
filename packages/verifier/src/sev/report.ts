import { hex, requireThat, zero } from '../quote/crypto.js';

export type Product = 'Genoa' | 'Turin';
export type TCB = { bl_spl: number; tee_spl: number; snp_spl: number; ucode_spl: number; fmc_spl?: number };
export function decodeTCB(value: bigint, product: Product): TCB {
  const byte = (shift: number) => Number((value >> BigInt(shift)) & 255n);
  if (product === 'Turin') {
    requireThat((value & 0x00ffffff00000000n) === 0n, 'nonzero reserved Turin TCB bits');
    return { fmc_spl: byte(0), bl_spl: byte(8), tee_spl: byte(16), snp_spl: byte(24), ucode_spl: byte(56) };
  }
  requireThat((value & 0x0000ffffffff0000n) === 0n, 'nonzero reserved Genoa TCB bits');
  return { bl_spl: byte(0), tee_spl: byte(8), snp_spl: byte(48), ucode_spl: byte(56) };
}
export const tcbAtLeast = (got: TCB, min: TCB): boolean => Object.entries(min).every(([k, v]) => (got[k as keyof TCB] ?? -1) >= v);

export class Report {
  readonly bytes: Uint8Array;
  readonly view: DataView;
  readonly product: Product;
  constructor(input: Uint8Array) {
    requireThat(input.length === 0x4a0, 'SEV-SNP report must be exactly 1184 bytes');
    this.bytes = Uint8Array.from(input); this.view = new DataView(this.bytes.buffer);
    requireThat(this.version >= 3 && this.version <= 5, 'unsupported SEV report version; CPUID report identity required');
    const family = this.bytes[0x188], model = this.bytes[0x189];
    if (family === 0x19 && model >> 4 === 1) this.product = 'Genoa';
    else if (family === 0x1a && model >> 4 <= 1) this.product = 'Turin';
    else throw new Error('unsupported AMD product identity');
    requireThat(this.u32(0x34) === 1, 'SEV report requires ECDSA P-384 SHA-384 signature');
    requireThat((this.policy & (1n << 17n)) !== 0n && (this.policy >> 26n) === 0n, 'invalid SEV guest policy reserved bits');
    requireThat((this.signerInfo & ~31) === 0 && (this.signerInfo >> 2) === 0, 'SEV report requires VCEK signing key');
    requireThat((this.signerInfo & 2) === 0 && !zero(this.chipID), 'masked or zero SEV platform identity');
    requireThat(this.platformInfo <= 255n, 'nonzero SEV PLATFORM_INFO reserved bits');
    for (const [lo, hi] of [[0x4c, 0x50], [0x18b, 0x1a0], [0x1eb, 0x1ec], [0x1ef, 0x1f0], [this.version < 5 ? 0x1f8 : 0x208, 0x2a0], [0x2d0, 0x2e8], [0x318, 0x4a0]]) {
      requireThat(zero(this.bytes.slice(lo, hi)), `nonzero reserved SEV report bytes at ${lo.toString(16)}`);
    }
    for (const offset of [0x38, 0x180, 0x1e0, 0x1f0]) decodeTCB(this.u64(offset), this.product);
  }
  u32(offset: number): number { return this.view.getUint32(offset, true); }
  u64(offset: number): bigint { return this.view.getBigUint64(offset, true); }
  field(offset: number, size: number): Uint8Array { return this.bytes.slice(offset, offset + size); }
  get version(): number { return this.u32(0); }
  get policy(): bigint { return this.u64(8); }
  get platformInfo(): bigint { return this.u64(0x40); }
  get signerInfo(): number { return this.u32(0x48); }
  get chipID(): Uint8Array { return this.field(0x1a0, 64); }
  get identity(): string { return hex(this.chipID); }
  get launch(): string { return hex(this.field(0x90, 48)); }
  get reportedTCB(): TCB { return decodeTCB(this.u64(0x180), this.product); }
}
