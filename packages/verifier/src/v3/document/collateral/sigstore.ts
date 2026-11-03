import { raw, str } from "../../internal/json/decode.js";
import type { JsonValue } from "../../internal/json/index.js";
import { unmarshalData, type Entry } from "./collateral.js";

/** A Sigstore reference-values entry. Repo and tag are hints; the bundle authenticates. */
export interface SigstoreRef {
  readonly repo: string;
  readonly tag: string;
  readonly digest: string;
  readonly bundle: JsonValue;
}

/** A freshness witness or approval bundle. */
export interface Freshness {
  readonly format: string;
  readonly bundle: JsonValue;
}

/** Requires a non-empty digest and a bundle. */
export function decodeSigstoreRef(entry: Entry): SigstoreRef {
  const data = unmarshalData(entry, entry.format, ["repo", "tag", "digest", "sigstore_bundle"], (o) => ({
    repo: str(o, "repo"),
    tag: str(o, "tag"),
    digest: str(o, "digest"),
    bundle: raw(o, "sigstore_bundle"),
  }));
  const digest = data.digest;
  // Tag is an optional hint and repo is checked by provenance where it
  // matters; the digest and bundle are what verification needs.
  if (digest === "") throw new Error(`${entry.format} collateral entry "${entry.id}" is missing digest`);
  const bundle = requireBundle(entry, data.bundle);
  return { repo: data.repo, tag: data.tag, digest, bundle };
}

/** Requires a bundle; records the entry's format. */
export function decodeFreshness(entry: Entry): Freshness {
  const bundle = unmarshalData(entry, entry.format, ["sigstore_bundle"], (o) => raw(o, "sigstore_bundle"));
  return { format: entry.format, bundle: requireBundle(entry, bundle) };
}

/** Rejects a missing or null sigstore_bundle. Whether it verifies is for provenance to judge. */
function requireBundle(entry: Entry, bundle: JsonValue | undefined): JsonValue {
  if (bundle === undefined || bundle === null) {
    throw new Error(`${entry.format} collateral entry "${entry.id}" is missing sigstore_bundle`);
  }
  return bundle;
}

