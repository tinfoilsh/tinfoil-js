import { decodeBase64, decodeLowerHex } from "../../internal/canonical.js";
import { raw, str } from "../../internal/json/decode.js";
import type { JsonValue } from "../../internal/json/index.js";
import { CONFIG_V1_FORMAT, unmarshalData, type Entry } from "./collateral.js";

/**
 * Decoded, unauthenticated config material. Plain config/v1 collateral has no
 * reference or bundle and requires caller authorization; a signed reference
 * must match the independently verified endorsement.
 */
export interface ConfigEndorsement {
  /** "sha256:<hex>" endorsement reference; "" for plain config/v1. */
  readonly reference: string;
  readonly config: Uint8Array;
  /** The sigstore_bundle member as sent; undefined when absent. */
  readonly bundle?: JsonValue;
}

export function decodeConfigEndorsement(entry: Entry): ConfigEndorsement {
  const c = unmarshalData(entry, entry.format, ["endorsement_ref", "config_base64", "sigstore_bundle"], (o) => ({
    reference: str(o, "endorsement_ref"),
    configBase64: str(o, "config_base64"),
    bundle: raw(o, "sigstore_bundle"),
  }));
  const { reference, bundle } = c;
  if (entry.format === CONFIG_V1_FORMAT) {
    // Go: c.Reference != "" || len(c.Bundle) != 0; an explicit null counts as present.
    if (reference !== "" || bundle !== undefined) {
      throw new Error("plain config collateral cannot contain an endorsement");
    }
  } else {
    if (!reference.startsWith("sha256:")) throw new Error("endorsement_ref must be a SHA-256 reference");
    decodeLowerHex("endorsement_ref", reference.slice("sha256:".length), 32);
    if (!(bundle instanceof Map)) throw new Error("sigstore_bundle must be an object");
  }
  const config = decodeBase64("config_base64", c.configBase64);
  if (config.length === 0) throw new Error("config_base64 must not be empty");
  return { reference, config, bundle };
}
