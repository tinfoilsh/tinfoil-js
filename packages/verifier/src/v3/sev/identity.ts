// The machines-map lookup key for a verified SEV-SNP report, a 1:1 port of
// Go verifier/quote/sev/identity.go.

import { encodeHex } from "../bytes.js";

// identity returns the machines-map lookup key for a verified SEV-SNP
// report's CHIP_ID field. The field is always 64 bytes; Turin hardware
// delivers its 8-byte hwID zero-padded, which is exactly the endorsed form,
// so no product-specific handling is needed. Throws a plain Error; the
// caller assigns the rejection layer.
export function identity(chipID: Uint8Array): string {
  if (chipID.length !== 64) {
    throw new Error(`SEV CHIP_ID must be 64 bytes, got ${chipID.length}`);
  }
  return encodeHex(chipID);
}
