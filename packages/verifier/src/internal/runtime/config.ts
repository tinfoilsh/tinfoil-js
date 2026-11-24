/** Reads the runtime pin from a Tinfoil config. */
import { RUNTIME_REPO, validateRuntimeReference, type RuntimeReference } from "../../document/collateral/runtime.js";
import { canonicalize, JsonNumber, strictParse, type JsonObject, type JsonValue } from "../json/index.js";
import * as semver from "../semver.js";
import { bytesEqual } from "../x509/certificate.js";

/**
 * The first cvm-version whose config is JSON. A config that pins it or a
 * later version is canonical JSON. Earlier versions measure YAML, which is
 * not read here.
 */
export const JSON_CONFIG_MIN_VERSION = "v0.15.5-rc.1";

const CVM_VERSION_KEY = "cvm-version";
const RUNTIME_DIGEST_SEPARATOR = "@sha256:";

/**
 * Reads the runtime pin of a JSON config: an object whose `cvm-version` is a
 * string, which is split on "@sha256:", its tag normalized to "v…", and
 * validated as a reference. The config must pin
 * {@link JSON_CONFIG_MIN_VERSION} or a later version and be in the one byte
 * form of a JSON config. Anything else rejects, including the YAML that
 * earlier versions measure.
 */
export function configRuntime(config: Uint8Array): RuntimeReference {
  const json = jsonConfig(config);
  if (json === undefined) {
    throw new Error(
      `parsing config runtime pin: not a JSON config that states cvm-version; the YAML configs of versions before ${JSON_CONFIG_MIN_VERSION} are not read`,
    );
  }
  const ref = runtimeFromPin(json.pin);
  if (semver.compare(ref.tag, JSON_CONFIG_MIN_VERSION) < 0) throw new Error(`a JSON config pins cvm-version ${JSON_CONFIG_MIN_VERSION} or later`);
  try {
    checkJsonConfigForm(config, json.value);
  } catch (err) {
    throw new Error(`parsing config runtime pin: ${(err as Error).message}`);
  }
  return ref;
}

function runtimeFromPin(pin: string): RuntimeReference {
  const at = pin.indexOf(RUNTIME_DIGEST_SEPARATOR);
  if (at < 0) throw new Error("cvm-version must pin a runtime manifest SHA-256 digest");
  const ref: RuntimeReference = {
    repo: RUNTIME_REPO,
    tag: runtimeTag(pin.slice(0, at)),
    digest: pin.slice(at + RUNTIME_DIGEST_SEPARATOR.length),
  };
  validateRuntimeReference(ref);
  return ref;
}

function runtimeTag(version: string): string {
  return "v" + version.replace(/^v/, "");
}

/** The config read as a JSON object and the `cvm-version` string it states; undefined when it is not one. */
function jsonConfig(config: Uint8Array): { readonly value: JsonObject; readonly pin: string } | undefined {
  let value: JsonValue;
  try {
    value = strictParse(config);
  } catch {
    return undefined;
  }
  if (!(value instanceof Map)) return undefined;
  const pin = value.get(CVM_VERSION_KEY);
  return typeof pin === "string" ? { value, pin } : undefined;
}

/**
 * Requires the one byte form a JSON config has: RFC 8785 canonical JSON
 * whose numbers are integers that every implementation reads exactly,
 * without null. No two parsers can then read its bytes differently.
 * `value` is `config` as parsed.
 */
function checkJsonConfigForm(config: Uint8Array, value: JsonValue): void {
  // A stack instead of recursion, filled in reverse so values are visited in document order.
  const pending: JsonValue[] = [value];
  for (let v = pending.pop(); v !== undefined; v = pending.pop()) {
    if (v === null) throw new Error("null is not allowed in a JSON config");
    if (v instanceof JsonNumber) {
      if (!isSafeInteger(v)) {
        throw new Error(`number ${v.raw} in a JSON config is not an integer between -(2^53-1) and 2^53-1`);
      }
    } else if (typeof v === "object") {
      const children = v instanceof Map ? Array.from((v as JsonObject).values()) : (v as readonly JsonValue[]);
      for (let i = children.length - 1; i >= 0; i--) pending.push(children[i]!);
    }
  }
  if (!bytesEqual(canonicalize(value), config)) throw new Error("JSON config is not in canonical form (RFC 8785)");
}

/** Whether the number's source literal is an integer within ±(2^53-1). */
function isSafeInteger(n: JsonNumber): boolean {
  try {
    n.toSafeInteger();
    return true;
  } catch {
    return false;
  }
}
