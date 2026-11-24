/** Reads the runtime pin from a Tinfoil config. */
import { RUNTIME_REPO, validateRuntimeReference, type RuntimeReference } from "../../document/collateral/runtime.js";
import { object, str } from "../json/decode.js";
import { strictParse } from "../json/index.js";

export const MAX_CONFIG_SIZE = 1 << 20;

/**
 * Reads the JSON `cvm-version` (exactly one document; other keys are
 * ignored, duplicate keys reject), splits it on "@sha256:", normalizes the
 * tag to "v…", and validates the reference.
 */
export function configRuntime(config: Uint8Array): RuntimeReference {
  const version = readCvmVersion(config);
  const at = version.indexOf("@sha256:");
  if (at < 0) throw new Error("cvm-version must pin a runtime manifest SHA-256 digest");
  const ref: RuntimeReference = {
    repo: RUNTIME_REPO,
    tag: "v" + version.slice(0, at).replace(/^v/, ""),
    digest: version.slice(at + "@sha256:".length),
  };
  validateRuntimeReference(ref);
  return ref;
}

/**
 * Reads the `cvm-version` value of the config: the stream must hold exactly
 * one document, an object; the value must be a string; an absent or null
 * value is "". Decode errors, including duplicate keys, reject.
 */
function readCvmVersion(config: Uint8Array): string {
  if (config.length > MAX_CONFIG_SIZE) throw new Error(`parsing config runtime pin: config exceeds ${MAX_CONFIG_SIZE} bytes`);
  try {
    return str(object(strictParse(config), "config"), "cvm-version");
  } catch (err) {
    throw new Error(`parsing config runtime pin: ${(err as Error).message}`);
  }
}
