import { decodeBase64, decodeLowerHex } from "../../internal/canonical.js";
import type { Reference } from "../../internal/endorsement/reference.js";
import { raw, str } from "../../internal/json/decode.js";
import type { JsonValue } from "../../internal/json/index.js";
import * as semver from "../../internal/semver.js";
import { unmarshalData, type Entry } from "./collateral.js";

export const RUNTIME_REPO = "tinfoilsh/cvmimage";
export const RUNTIME_ID = "runtime";
export const RUNTIME_V1_FORMAT = "https://tinfoil.sh/collateral/igvm-runtime/v1";
export const PLATFORM_ID = "platform";

/** A runtime release pin: a runtime release is named the same way as a code release. */
export type RuntimeReference = Reference;

/** Repo must be cvmimage, tag a full semver, digest 32-byte lowercase hex. */
export function validateRuntimeReference(r: RuntimeReference): void {
  if (r.repo !== RUNTIME_REPO) throw new Error(`runtime repository must be ${RUNTIME_REPO}`);
  if (!semver.isValid(r.tag) || semver.canonical(r.tag) + semver.build(r.tag) !== r.tag) {
    throw new Error("runtime tag must be a full semantic version");
  }
  decodeLowerHex("runtime digest", r.digest, 32);
}

/** Field-by-field equality of two runtime references; used by the provenance layer's runtime authentication. */
export function runtimeReferenceEqual(a: RuntimeReference, b: RuntimeReference): boolean {
  return a.repo === b.repo && a.tag === b.tag && a.digest === b.digest;
}

/** Decoded runtime collateral. */
export interface RuntimeCollateral extends RuntimeReference {
  readonly manifest: Uint8Array;
  readonly bundle: JsonValue;
}

export function decodeRuntime(entry: Entry): RuntimeCollateral {
  const c = unmarshalData(entry, entry.format, ["repo", "tag", "digest", "manifest_base64", "sigstore_bundle"], (o) => ({
    ref: { repo: str(o, "repo"), tag: str(o, "tag"), digest: str(o, "digest") },
    manifestBase64: str(o, "manifest_base64"),
    bundle: raw(o, "sigstore_bundle"),
  }));
  const { ref, bundle } = c;
  validateRuntimeReference(ref);
  // An empty manifest is accepted here: decoding checks shape only, and it
  // fails the manifest digest check when the runtime is authenticated.
  const manifest = decodeBase64("manifest_base64", c.manifestBase64);
  if (!(bundle instanceof Map)) throw new Error("sigstore_bundle must be an object");
  return { ...ref, manifest, bundle };
}
