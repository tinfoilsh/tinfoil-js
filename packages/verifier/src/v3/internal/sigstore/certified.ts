/**
 * Certificate-signed approval bundles: a DSSE envelope signed under a
 * short-lived registry certificate rather than a pinned key. The bundle's
 * RFC 3161 timestamp over the DSSE signature establishes when the signature
 * was made; the caller authenticates the certificate at that time. The log
 * entries follow the key-signed layout, with the certificate as the entry's
 * verifier.
 */
import { sha256, toHex } from "../bytes.js";
import type { Certificate } from "../x509/certificate.js";
import { IN_TOTO_PAYLOAD_TYPE, type Bundle } from "./bundle.js";
import { checkLayout, importP256, keyHint, statementNamesDigest, toBase64, verifyLogEntries, verifyP256 } from "./keyed.js";
import { preAuthEncoding, verifyTimestamp } from "./timestamp.js";
import type { TrustedRoot } from "./trusted-root.js";

/**
 * The time the first verifying RFC 3161 timestamp in `bundle` states for the
 * DSSE signature, under a timestamp authority of `root`. A bundle with no
 * verifying timestamp rejects.
 */
export async function signedTimestamp(root: TrustedRoot, bundle: Bundle): Promise<Date> {
  const failures: string[] = [];
  for (let i = 0; i < bundle.rfc3161Timestamps.length; i++) {
    try {
      return await verifyTimestamp(root, bundle.rfc3161Timestamps[i], bundle.dsse.signature);
    } catch (err) {
      failures.push(`timestamp ${i}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  throw new Error(`no RFC 3161 timestamp over the signature verifies${failures.length === 0 ? "" : ` (${failures.join("; ")})`}`);
}

/**
 * Verifies a certificate-signed DSSE bundle whose signing certificate the
 * caller has already authenticated as `leaf`: the layout (one to eight
 * hashedrekord 0.0.2 entries with proofs, at least one RFC 3161 timestamp),
 * the certificate in the bundle being `leaf`, the DSSE signature under the
 * certificate's P-256 key, every log entry naming this envelope and
 * certificate, and the statement naming `digest`. Returns the hint of the
 * certificate's key.
 */
export async function verifyCertifiedBundle(root: TrustedRoot, bundle: Bundle, leaf: Certificate, digest: Uint8Array): Promise<string> {
  if (bundle.certificate === undefined) throw new Error("certified approval bundle must carry a signing certificate");
  if (bundle.dsse.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
    throw new Error(`unsupported DSSE payload type ${JSON.stringify(bundle.dsse.payloadType)}`);
  }
  if (bundle.dsse.keyId !== "") throw new Error("DSSE key id must be empty for a certificate-signed bundle");
  if (digest.length !== 32) throw new Error("expected artifact digest is not SHA-256");
  checkLayout(bundle, "required");

  const key = await importP256(leaf.spki);
  const signed = preAuthEncoding(bundle.dsse.payloadType, bundle.dsse.payload);
  if (!(await verifyP256(key, bundle.dsse.signature, signed))) {
    throw new Error("DSSE signature does not verify under the signing certificate");
  }

  await verifyLogEntries(root, bundle, {
    digest: toBase64(await sha256(signed)),
    signature: toBase64(bundle.dsse.signature),
    verifier: { x509Certificate: toBase64(bundle.certificate) },
  });

  if (!statementNamesDigest(bundle.dsse.payload, toHex(digest))) {
    throw new Error("the statement's subjects do not name the artifact digest");
  }
  return keyHint(leaf.spki);
}
