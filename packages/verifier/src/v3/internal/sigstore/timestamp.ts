/** RFC 3161 timestamps from the trusted root's timestamp authorities, and the canonical input they sign. */
import { notImplemented } from "../../errors.js";
import type { JsonValue } from "../json/index.js";
import type { TrustedRoot } from "./trusted-root.js";

/** The policy OID a Sigstore timestamp authority must state. */
export const SIGSTORE_TIMESTAMP_POLICY = "1.3.6.1.4.1.57264.2";
export const MAX_TIMESTAMP_SIZE = 64 << 10;
export const MAX_STATEMENT_SIZE = 128 << 10;

/**
 * The bytes a timestamp covers for a statement: `domain` followed by the
 * RFC 8785 canonical form of `core`.
 */
export function timestampInput(domain: string, core: JsonValue): Uint8Array {
  return notImplemented("sigstore.timestampInput");
}

/**
 * Verifies a timestamp response over `input`: the message imprint is SHA-256
 * of `input`, the policy OID is the Sigstore one, and some authority in
 * `root` signed it and was valid at the stated time. Returns that time.
 */
export async function verifyTimestamp(root: TrustedRoot, response: Uint8Array, input: Uint8Array): Promise<Date> {
  return notImplemented("sigstore.verifyTimestamp");
}

/** "sha256:" + hex SHA-256 of the DSSE pre-authentication encoding of an in-toto payload. */
export async function endorsementReference(payload: Uint8Array): Promise<string> {
  return notImplemented("sigstore.endorsementReference");
}
