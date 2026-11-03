/**
 * Key-signed bundle verification for approvals signed with a pinned key:
 * no certificate, a public-key hint, between one and eight hashedrekord
 * 0.0.2 log entries each with an inclusion proof and no promise, no
 * integration times, and no RFC 3161 timestamps inside the bundle.
 */
import { notImplemented } from "../../errors.js";
import type { Bundle } from "./bundle.js";
import type { TrustedRoot } from "./trusted-root.js";

export const MAX_LOG_RECEIPTS = 8;

/** A pinned P-256 verification key and the hint that names it. */
export interface PinnedKey {
  readonly hint: string;
  readonly key: CryptoKey;
}

/** base64 SHA-256 of the DER public key: the hint a bundle names a key by. */
export async function keyHint(spki: Uint8Array): Promise<string>;
export async function keyHint(key: CryptoKey): Promise<string>;
export async function keyHint(key: Uint8Array | CryptoKey): Promise<string> {
  return notImplemented("sigstore.keyHint");
}

/** Imports PEM-encoded P-256 public keys as pinned keys, deduplicated by hint. */
export async function pinnedKeys(pems: readonly string[]): Promise<PinnedKey[]> {
  return notImplemented("sigstore.pinnedKeys");
}

/**
 * Verifies a key-signed DSSE bundle: the layout above, the key hint naming
 * one of `keys` (and the DSSE key id, if set, equal to it), every log entry's
 * body consistent with the envelope and its inclusion proof and checkpoint
 * valid for a log in `root`, and the DSSE signature over the payload. Returns
 * the hint of the key that verified.
 */
export async function verifyKeyedBundle(root: TrustedRoot, bundle: Bundle, keys: readonly PinnedKey[], digest: Uint8Array): Promise<string> {
  return notImplemented("sigstore.verifyKeyedBundle");
}
