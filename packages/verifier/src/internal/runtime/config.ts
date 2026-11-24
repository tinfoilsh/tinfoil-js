/** Reads the runtime pin from a Tinfoil config. */
import { isAlias, isMap, isScalar, parseAllDocuments } from "yaml";
import { RUNTIME_REPO, validateRuntimeReference, type RuntimeReference } from "../../document/collateral/runtime.js";
import { canonicalize, JsonNumber, strictParse, type JsonObject, type JsonValue } from "../json/index.js";
import * as semver from "../semver.js";
import { bytesEqual } from "../x509/certificate.js";

/**
 * The first cvm-version whose config is JSON. A config that pins it or a
 * later version is canonical JSON, and YAML is refused; earlier versions
 * keep YAML.
 */
export const JSON_CONFIG_MIN_VERSION = "v0.15.5-rc.1";

const CVM_VERSION_KEY = "cvm-version";
const RUNTIME_DIGEST_SEPARATOR = "@sha256:";

/**
 * Reads the `cvm-version` pin, splits it on "@sha256:", normalizes the tag
 * to "v…", and validates the reference. A JSON object that pins
 * {@link JSON_CONFIG_MIN_VERSION} or a later version must be in the one
 * byte form of a JSON config. Anything else is read as YAML (exactly one
 * document; other keys are ignored, duplicate keys reject), and YAML that
 * pins such a version rejects.
 */
export function configRuntime(config: Uint8Array): RuntimeReference {
  const json = jsonConfig(config);
  if (json !== undefined && requiresJson(json.pin)) {
    try {
      checkJsonConfigForm(config, json.value);
    } catch (err) {
      throw new Error(`parsing config runtime pin: ${(err as Error).message}`);
    }
    return runtimeFromPin(json.pin);
  }
  const version = readCvmVersion(config);
  const ref = runtimeFromPin(version);
  if (requiresJson(version)) throw new Error(`cvm-version ${JSON_CONFIG_MIN_VERSION} and later take a JSON config`);
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

/** Whether a config with this cvm-version must be JSON. A version that is not valid does not require it. */
function requiresJson(pin: string): boolean {
  const at = pin.indexOf(RUNTIME_DIGEST_SEPARATOR);
  return semver.compare(runtimeTag(at < 0 ? pin : pin.slice(0, at)), JSON_CONFIG_MIN_VERSION) >= 0;
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

/**
 * Reads the `cvm-version` value of the config: the stream must hold exactly
 * one document, a mapping; the value must be a scalar (any scalar reads as
 * its text); an absent or null value is "". Decode errors, including
 * duplicate keys, reject.
 */
function readCvmVersion(config: Uint8Array): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(config);
  } catch {
    throw new Error("parsing config runtime pin: config is not valid UTF-8");
  }
  const docs = parseAllDocuments(text, { uniqueKeys: true });
  if (!Array.isArray(docs) || docs.length === 0) throw new Error("parsing config runtime pin: EOF");
  if (docs.length !== 1) throw new Error("config must contain exactly one YAML document");
  const doc = docs[0]!;
  if (doc.errors.length > 0) throw new Error(`parsing config runtime pin: ${doc.errors[0]!.message}`);
  const root = doc.contents;
  if (root === null) return "";
  if (!isMap(root)) throw new Error("parsing config runtime pin: config is not a mapping");
  let node: unknown = root.get(CVM_VERSION_KEY, true);
  if (node === undefined || node === null) return "";
  // An alias reads as its anchored node.
  if (isAlias(node)) node = node.resolve(doc);
  if (!isScalar(node)) throw new Error("parsing config runtime pin: cvm-version must be a scalar");
  if (node.value === null) return "";
  return node.source ?? String(node.value);
}
