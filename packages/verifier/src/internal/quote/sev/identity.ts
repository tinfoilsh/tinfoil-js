import { toHex } from "../../bytes.js";
import { CHIP_ID_SIZE } from "./report.js";

/**
 * The platform identity of an SEV-SNP machine: its 64-byte CHIP_ID as
 * lowercase hex. Turin hardware delivers an 8-byte id zero-padded to 64
 * bytes, which is the endorsed form, so no product-specific handling applies.
 */
export function identity(chipId: Uint8Array): string {
  if (chipId.length !== CHIP_ID_SIZE) throw new Error(`SEV CHIP_ID must be ${CHIP_ID_SIZE} bytes, got ${chipId.length}`);
  return toHex(chipId);
}
