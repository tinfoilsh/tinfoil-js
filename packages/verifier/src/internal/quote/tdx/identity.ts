import { toHex } from "../../bytes.js";
import type { Certificate } from "../../x509/certificate.js";
import { pckExtensions } from "./pck.js";

/**
 * The platform identity of a TDX machine: the 16-byte PPID from the SGX
 * extension of the PCK leaf certificate, lowercase hex. The leaf must have
 * been authenticated to the Intel root first; this only reads it.
 */
export function identity(leaf: Certificate): string {
  return toHex(pckExtensions(leaf).ppid);
}
