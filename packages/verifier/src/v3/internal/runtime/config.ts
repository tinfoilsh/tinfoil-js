/** Reads the runtime pin from a Tinfoil config. Mirrors tinfoil-go verify/internal/runtime/config.go. */
import { isAlias, isMap, isScalar, parseAllDocuments } from "yaml";
import { RUNTIME_REPO, validateRuntimeReference, type RuntimeReference } from "../../document/collateral/runtime.js";

/**
 * Reads the YAML `cvm-version` (exactly one document; other keys are
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
 * Decodes the config as yaml.v3 does into `struct{ Version string
 * "cvm-version" }`: the stream must hold exactly one document, a mapping;
 * the value must be a scalar (any scalar reads as its text); an absent or
 * null value is "". Decode errors, including duplicate keys, reject.
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
  let node: unknown = root.get("cvm-version", true);
  if (node === undefined || node === null) return "";
  // yaml.v3 resolves an alias to its anchored node before decoding it.
  if (isAlias(node)) node = node.resolve(doc);
  if (!isScalar(node)) throw new Error("parsing config runtime pin: cvm-version must be a scalar");
  if (node.value === null) return "";
  return node.source ?? String(node.value);
}
