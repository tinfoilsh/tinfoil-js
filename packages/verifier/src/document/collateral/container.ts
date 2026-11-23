import { decodeLowerHex } from "../../internal/canonical.js";
import { raw, str } from "../../internal/json/decode.js";
import type { JsonValue } from "../../internal/json/index.js";
import { unmarshalData, type Entry } from "./collateral.js";
import { requireBundle } from "./sigstore.js";

/** Carries the build attestation of one container image {digest, sigstore_bundle}, for a config that requires one. */
export const CONTAINER_PROVENANCE_V1_FORMAT = "https://tinfoil.sh/collateral/container-provenance/v1";

const SHA256_SIZE = 32;

/** A decoded, unauthenticated build attestation for the image with the lowercase hex SHA-256 `digest`. */
export interface ContainerProvenanceCollateral {
  readonly digest: string;
  readonly bundle: JsonValue;
}

export function decodeContainerProvenance(entry: Entry): ContainerProvenanceCollateral {
  const data = unmarshalData(entry, entry.format, ["digest", "sigstore_bundle"], (o) => ({
    digest: str(o, "digest"),
    bundle: raw(o, "sigstore_bundle"),
  }));
  decodeLowerHex("container digest", data.digest, SHA256_SIZE);
  return { digest: data.digest, bundle: requireBundle(entry, data.bundle) };
}
