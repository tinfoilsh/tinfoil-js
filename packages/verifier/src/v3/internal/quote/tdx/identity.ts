import { notImplemented } from "../../../errors.js";
import type { ParsedQuote } from "./authenticate.js";

/** The platform identity of a TDX machine: the 16-byte PPID from the PCK leaf certificate, lowercase hex. */
export function identity(quote: ParsedQuote): string {
  return notImplemented("tdx.identity");
}
