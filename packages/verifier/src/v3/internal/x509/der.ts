/**
 * Strict DER: definite lengths in minimal form, minimal integers, BOOLEAN
 * as 0x00 or 0xFF, and UTCTime/GeneralizedTime with a trailing 'Z'. Anything
 * BER-only is rejected, so two encodings of one value can't both verify.
 */
import { notImplemented } from "../../errors.js";

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

/** Decodes exactly one element from `bytes`; trailing bytes reject. */
export function decode(bytes: Uint8Array): DerElement {
  return notImplemented("der.decode");
}

/** Decodes the elements of a SEQUENCE or SET's content, in order. */
export function children(e: DerElement): DerElement[] {
  return notImplemented("der.children");
}

/** A non-negative INTEGER as bigint; non-minimal encodings reject. */
export function integer(e: DerElement): bigint {
  return notImplemented("der.integer");
}

/** An OBJECT IDENTIFIER in dotted form. */
export function oid(e: DerElement): string {
  return notImplemented("der.oid");
}

/** A UTCTime or GeneralizedTime; both require the 'Z' suffix. */
export function time(e: DerElement): Date {
  return notImplemented("der.time");
}

/** A BIT STRING's bytes; the unused-bits count must be 0. */
export function bitString(e: DerElement): Uint8Array {
  return notImplemented("der.bitString");
}

export function boolean(e: DerElement): boolean {
  return notImplemented("der.boolean");
}

/** Splits a PEM file into the DER bodies of its blocks of the given label, in order. */
export function pemBlocks(pem: string, label: string): Uint8Array[] {
  return notImplemented("der.pemBlocks");
}

/** Converts an ECDSA signature from DER (SEQUENCE of two minimal INTEGERs) to fixed-width r‖s. */
export function ecdsaSignatureToRaw(der: Uint8Array, coordinateBytes: number): Uint8Array {
  return notImplemented("der.ecdsaSignatureToRaw");
}
