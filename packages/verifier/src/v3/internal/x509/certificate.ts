/** X.509 certificates: strict parsing, signature verification and the extensions the verifier reads. */
import { notImplemented } from "../../errors.js";

export type SignatureAlgorithm = "ecdsa-p256-sha256" | "ecdsa-p384-sha384" | "rsa-pss-sha384" | "rsa-pkcs1-sha256";

/** One extension; `critical` defaults to false when absent. */
export interface Extension {
  readonly oid: string;
  readonly critical: boolean;
  readonly value: Uint8Array;
}

export interface Certificate {
  /** The whole DER certificate. */
  readonly raw: Uint8Array;
  /** The DER TBSCertificate, the bytes the signature covers. */
  readonly tbs: Uint8Array;
  readonly serialNumber: bigint;
  /** Issuer and subject as DER Name, for byte-exact chain matching. */
  readonly issuer: Uint8Array;
  readonly subject: Uint8Array;
  /** The subject's CN, when present. */
  readonly subjectCommonName?: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  /** The DER SubjectPublicKeyInfo. */
  readonly spki: Uint8Array;
  readonly signatureAlgorithm: SignatureAlgorithm;
  readonly signature: Uint8Array;
  readonly extensions: readonly Extension[];
}

/** Parses a DER certificate. Unknown critical extensions do not reject here; callers decide. */
export function parseCertificate(der: Uint8Array): Certificate {
  return notImplemented("x509.parseCertificate");
}

/** Verifies `cert`'s signature with the issuer's public key. */
export async function verifyCertificateSignature(cert: Certificate, issuerSpki: Uint8Array): Promise<boolean> {
  return notImplemented("x509.verifyCertificateSignature");
}

/** The extension with the given OID, if present. */
export function extension(cert: Certificate, oid: string): Extension | undefined {
  return notImplemented("x509.extension");
}

/**
 * Verifies a chain leaf → … → root: each signature with the next
 * certificate's key, issuer/subject names matching byte for byte, every
 * certificate valid at `at`, and every issuing certificate (intermediates and
 * the root) asserting basicConstraints cA. The root must be one of `roots`.
 */
export async function verifyChain(chain: readonly Certificate[], roots: readonly Certificate[], at: Date): Promise<void> {
  return notImplemented("x509.verifyChain");
}

/** SHA-256 of the DER SubjectPublicKeyInfo, lowercase hex: the TLS pinning fingerprint form. */
export async function spkiFingerprint(spki: Uint8Array): Promise<string> {
  return notImplemented("x509.spkiFingerprint");
}
