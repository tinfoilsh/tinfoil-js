import { notImplemented } from "../../../errors.js";

/** The platform identity of an SEV-SNP machine: its 64-byte CHIP_ID as lowercase hex. */
export function identity(chipId: Uint8Array): string {
  return notImplemented("sev.identity");
}
