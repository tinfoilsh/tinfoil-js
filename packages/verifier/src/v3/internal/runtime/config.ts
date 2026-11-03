/** Reads the runtime pin from a Tinfoil config. Mirrors tinfoil-go verify/internal/runtime/config.go. */
import type { RuntimeReference } from "../../document/collateral/runtime.js";
import { notImplemented } from "../../errors.js";

/**
 * Reads the YAML `cvm-version` (exactly one document), splits it on
 * "@sha256:", normalizes the tag to "v…", and validates the reference.
 */
export function configRuntime(config: Uint8Array): RuntimeReference {
  return notImplemented("runtime.configRuntime");
}
