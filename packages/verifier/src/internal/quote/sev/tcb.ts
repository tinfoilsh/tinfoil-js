/**
 * TCB_VERSION values: a 64-bit bitfield of security patch levels whose
 * layout depends on the product line. Genoa uses layout 0 (microcode,
 * SNP, four reserved levels, TEE, bootloader); Turin uses layout 1
 * (microcode, 24 reserved bits, SNP, TEE, bootloader, FMC).
 */
import { PRODUCT_GENOA, PRODUCT_TURIN, type ProductLine } from "./report.js";

export const TCB_LAYOUT_0 = 0;
export const TCB_LAYOUT_1 = 1;
export type TcbLayout = typeof TCB_LAYOUT_0 | typeof TCB_LAYOUT_1;

/** Security patch levels, tagged with the layout they were read in. */
export interface TcbParts {
  readonly layout: TcbLayout;
  readonly blSpl: number;
  readonly teeSpl: number;
  readonly spl4: number;
  readonly spl5: number;
  readonly spl6: number;
  readonly spl7: number;
  readonly snpSpl: number;
  readonly ucodeSpl: number;
  readonly fmcSpl: number;
}

/** The TCB layout a product line's firmware and certificates use. */
export function tcbLayoutOf(product: ProductLine): TcbLayout {
  switch (product) {
    case PRODUCT_GENOA:
      return TCB_LAYOUT_0;
    case PRODUCT_TURIN:
      return TCB_LAYOUT_1;
  }
}

const byteAt = (tcb: bigint, shift: bigint): number => Number((tcb >> shift) & 0xffn);

/** Splits a 64-bit TCB into its levels under `layout`; non-zero reserved bits of layout 1 reject. */
export function decomposeTcb(layout: TcbLayout, tcb: bigint): TcbParts {
  switch (layout) {
    case TCB_LAYOUT_1: {
      const reserved = tcb & 0x00ffffff00000000n;
      if (reserved !== 0n) throw new Error(`non-zero reserved bits in Turin TCB: 0x${reserved.toString(16)}`);
      return {
        layout,
        ucodeSpl: byteAt(tcb, 56n),
        snpSpl: byteAt(tcb, 24n),
        teeSpl: byteAt(tcb, 16n),
        blSpl: byteAt(tcb, 8n),
        fmcSpl: byteAt(tcb, 0n),
        spl4: 0,
        spl5: 0,
        spl6: 0,
        spl7: 0,
      };
    }
    case TCB_LAYOUT_0:
      return {
        layout,
        ucodeSpl: byteAt(tcb, 56n),
        snpSpl: byteAt(tcb, 48n),
        spl7: byteAt(tcb, 40n),
        spl6: byteAt(tcb, 32n),
        spl5: byteAt(tcb, 24n),
        spl4: byteAt(tcb, 16n),
        teeSpl: byteAt(tcb, 8n),
        blSpl: byteAt(tcb, 0n),
        fmcSpl: 0,
      };
  }
}

/**
 * Recomposes levels into a 64-bit TCB. Every level but the microcode one
 * must fit 7 bits; layout 0 has no FMC level and layout 1 no reserved ones.
 */
export function composeTcb(parts: TcbParts): bigint {
  const check127 = (name: string, value: number): void => {
    if (value > 127) throw new Error(`${name} TCB part is ${value}. Expect 0-127`);
  };
  check127("SnpSpl", parts.snpSpl);
  check127("Spl7", parts.spl7);
  check127("Spl6", parts.spl6);
  check127("Spl5", parts.spl5);
  check127("Spl4", parts.spl4);
  check127("TeeSpl", parts.teeSpl);
  check127("BlSpl", parts.blSpl);
  check127("FmcSpl", parts.fmcSpl);
  const b = (v: number, shift: bigint): bigint => BigInt(v) << shift;
  switch (parts.layout) {
    case TCB_LAYOUT_0:
      if (parts.fmcSpl !== 0) throw new Error("FmcSpl is not defined for TCB struct version 0");
      return (
        b(parts.ucodeSpl, 56n) |
        b(parts.snpSpl, 48n) |
        b(parts.spl7, 40n) |
        b(parts.spl6, 32n) |
        b(parts.spl5, 24n) |
        b(parts.spl4, 16n) |
        b(parts.teeSpl, 8n) |
        b(parts.blSpl, 0n)
      );
    case TCB_LAYOUT_1:
      if (parts.spl4 !== 0 || parts.spl5 !== 0 || parts.spl6 !== 0 || parts.spl7 !== 0) {
        throw new Error("reserved Turin TCB components must be zero");
      }
      return b(parts.ucodeSpl, 56n) | b(parts.snpSpl, 24n) | b(parts.teeSpl, 16n) | b(parts.blSpl, 8n) | b(parts.fmcSpl, 0n);
  }
}

/** Whether every level of `a` is at most the corresponding level of `b`, in the same layout. */
export function tcbLe(a: TcbParts, b: TcbParts): boolean {
  return (
    a.layout === b.layout &&
    a.ucodeSpl <= b.ucodeSpl &&
    a.snpSpl <= b.snpSpl &&
    a.spl7 <= b.spl7 &&
    a.spl6 <= b.spl6 &&
    a.spl5 <= b.spl5 &&
    a.spl4 <= b.spl4 &&
    a.teeSpl <= b.teeSpl &&
    a.blSpl <= b.blSpl &&
    a.fmcSpl <= b.fmcSpl
  );
}

/** Renders levels for error messages. */
export function formatTcb(p: TcbParts): string {
  const fmc = p.layout === TCB_LAYOUT_1 ? ` FmcSpl:${p.fmcSpl}` : "";
  return `{BlSpl:${p.blSpl} TeeSpl:${p.teeSpl} SnpSpl:${p.snpSpl} UcodeSpl:${p.ucodeSpl}${fmc}}`;
}
