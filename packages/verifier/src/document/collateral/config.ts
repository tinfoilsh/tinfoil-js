import { decodeBase64, decodeLowerHex } from "../../internal/canonical.js";
import { raw, str } from "../../internal/json/decode.js";
import { sourceText } from "../../internal/json/index.js";
import { CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_V1_FORMAT, unmarshalData, type Entry } from "./collateral.js";

/**
 * Decoded, unauthenticated config material. Plain config/v1 collateral has no
 * reference or bundle and requires caller authorization; a signed reference
 * must match the independently verified endorsement. Only v2 endorsement
 * collateral may carry a registry issuer certificate or omit the config
 * bytes (a digest-only deployment).
 */
export interface ConfigEndorsement {
  /** "sha256:<hex>" endorsement reference; "" for plain config/v1. */
  readonly reference: string;
  /** The exact config bytes; absent for a digest-only v2 endorsement. */
  readonly config?: Uint8Array;
  /**
   * The sigstore_bundle member's JSON text as sent, byte for byte as it
   * appears in the document; undefined when absent. `JSON.parse` turns it
   * into a plain object.
   */
  readonly bundle?: string;
  /** The DER certificate of the registry issuer that certified the signing certificate, when present. */
  readonly issuer?: Uint8Array;
}

const MEMBERS = ["endorsement_ref", "config_base64", "sigstore_bundle", "issuer_certificate_der"];

export function decodeConfigEndorsement(entry: Entry): ConfigEndorsement {
  const c = unmarshalData(entry, entry.format, MEMBERS, (o) => ({
    reference: str(o, "endorsement_ref"),
    configBase64: str(o, "config_base64"),
    bundle: raw(o, "sigstore_bundle"),
    issuerBase64: str(o, "issuer_certificate_der"),
  }));
  const { reference } = c;
  if (c.issuerBase64 !== "" && entry.format !== CONFIG_ENDORSEMENT_V2_FORMAT) {
    throw new Error("issuer certificates require v2 config collateral");
  }
  let bundle: string | undefined;
  if (entry.format === CONFIG_V1_FORMAT) {
    // A non-empty reference or any sigstore_bundle member, including an explicit null, counts as an endorsement.
    if (reference !== "" || c.bundle !== undefined) {
      throw new Error("plain config collateral cannot contain an endorsement");
    }
  } else {
    if (!reference.startsWith("sha256:")) throw new Error("endorsement_ref must be a SHA-256 reference");
    decodeLowerHex("endorsement_ref", reference.slice("sha256:".length), 32);
    if (!(c.bundle instanceof Map)) throw new Error("sigstore_bundle must be an object");
    // The bundle travels on as the member's source text; the approval
    // verifier parses it again, strictly, when it needs the tree.
    bundle = sourceText(c.bundle);
    if (bundle === undefined) throw new Error("sigstore_bundle has no source text");
  }
  const issuer = c.issuerBase64 === "" ? undefined : decodeBase64("issuer_certificate_der", c.issuerBase64);
  const optional = { ...(bundle === undefined ? {} : { bundle }), ...(issuer === undefined ? {} : { issuer }) };
  if (entry.format === CONFIG_ENDORSEMENT_V2_FORMAT && c.configBase64 === "") {
    return { reference, ...optional };
  }
  const config = decodeBase64("config_base64", c.configBase64);
  if (config.length === 0) throw new Error("config_base64 must not be empty");
  return { reference, config, ...optional };
}
