/** Reads the runtime pin from a Tinfoil config. */
import { RUNTIME_REPO, validateRuntimeReference, type RuntimeReference } from "../../document/collateral/runtime.js";
import { strictParse, type JsonValue } from "../json/index.js";

export const MAX_CONFIG_SIZE = 1 << 20;

const CVM_VERSION_KEY = "cvm-version";

/**
 * Reads the `cvm-version` of a JSON config (other members are ignored),
 * splits it on "@sha256:", normalizes the tag to "v…", and validates the
 * reference.
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
 * Reads the `cvm-version` value of the config: the bytes must be at most
 * {@link MAX_CONFIG_SIZE} and strictly parse as one JSON object, and the
 * value must be a string. Anything else rejects, including a YAML config.
 */
function readCvmVersion(config: Uint8Array): string {
  if (config.length > MAX_CONFIG_SIZE) throw new Error(`parsing config runtime pin: the config is larger than ${MAX_CONFIG_SIZE} bytes`);
  let version: JsonValue | undefined;
  try {
    const value = strictParse(config);
    if (value instanceof Map) version = value.get(CVM_VERSION_KEY);
  } catch {
    // Bytes that are not JSON state no cvm-version.
  }
  if (typeof version !== "string") {
    throw new Error("parsing config runtime pin: not a JSON config that states cvm-version; YAML configs are not read");
  }
  return version;
}
