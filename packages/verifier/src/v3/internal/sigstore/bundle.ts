/**
 * Sigstore bundle wire checks shared by every bundle kind: version 0.3 media
 * type, verification material, exactly one DSSE signature, and the shape of
 * transparency-log entries.
 */
import { notImplemented } from "../../errors.js";
import type { JsonValue } from "../json/index.js";

export const BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
export const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const MAX_BUNDLE_SIZE = 4 << 20;

export interface TlogEntry {
  readonly logId: string;
  readonly kind: string;
  readonly version: string;
  /** Seconds since the epoch; absent for entries anchored by a timestamp instead. */
  readonly integratedTime?: bigint;
  readonly canonicalizedBody: Uint8Array;
  readonly inclusionPromise?: Uint8Array;
  readonly inclusionProof?: InclusionProof;
}

export interface InclusionProof {
  readonly logIndex: bigint;
  readonly rootHash: Uint8Array;
  readonly treeSize: bigint;
  readonly hashes: readonly Uint8Array[];
  readonly checkpoint: string;
}

/** A bundle decoded far enough to route it: the parts every verifier reads. */
export interface Bundle {
  readonly json: JsonValue;
  readonly mediaType: string;
  /** DER leaf certificate, for certificate-signed bundles. */
  readonly certificate?: Uint8Array;
  /** The key hint, for key-signed bundles. */
  readonly publicKeyHint?: string;
  readonly tlogEntries: readonly TlogEntry[];
  readonly rfc3161Timestamps: readonly Uint8Array[];
  readonly dsse: { readonly payloadType: string; readonly payload: Uint8Array; readonly signature: Uint8Array; readonly keyId: string };
}

/**
 * Decodes a bundle and enforces the shared rules: version 0.3 media type; a
 * certificate or a key hint but not the legacy certificate-chain layout; a
 * DSSE envelope with exactly one signature.
 */
export function parseBundle(json: JsonValue): Bundle {
  return notImplemented("sigstore.parseBundle");
}

/** Serializes a parsed bundle value for the Sigstore library. */
export function bundleBytes(json: JsonValue): Uint8Array {
  return notImplemented("sigstore.bundleBytes");
}
