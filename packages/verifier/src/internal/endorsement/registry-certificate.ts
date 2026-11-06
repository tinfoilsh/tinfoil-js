/**
 * Registry signing certificates: a short-lived certificate, issued by a
 * self-signed registry root whose key is pinned, that assigns one registry
 * ID (a URI) to the key approving a config. The profile is narrow so that
 * only a certificate made for this purpose can be used for it.
 */
import { keyHint, type PinnedKey } from "../sigstore/keyed.js";
import {
  basicConstraints,
  bytesEqual,
  canIssueCertificates,
  expectSequence,
  extension,
  keyUsage,
  parseCertificate,
  unsupportedCriticalExtension,
  verifyCertificateSignature,
  verifyChain,
  X509Error,
  type Certificate,
} from "../x509/certificate.js";
import { CLASS_CONTEXT, decode, DerError, oid } from "../x509/der.js";

export const MAX_CERTIFICATE_SIZE = 16 << 10;
/** The longest a registry signing certificate may be valid for. */
export const CERTIFICATE_VALIDITY_MS = 10 * 60 * 1000;
/** How far an approval's inner timestamp may follow the certificate-signed signature time. */
export const CERTIFICATE_CLOCK_SKEW_MS = 60 * 1000;

const OID_SUBJECT_ALT_NAME = "2.5.29.17";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
const OID_KP_ANY = "2.5.29.37.0";
/** Fulcio's OIDC issuer extensions; a registry certificate carries neither. */
const OID_FULCIO_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1";
const OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
const URI_GENERAL_NAME_TAG = 6;
const KEY_USAGE_DIGITAL_SIGNATURE = 0;
/** An empty Name: SEQUENCE of no RDNs. */
const EMPTY_NAME = new Uint8Array([0x30, 0x00]);

export interface RegistryCertificate {
  readonly certificate: Certificate;
  readonly issuer: Certificate;
  /** The registry ID the certificate's single URI SAN names. */
  readonly registryID: string;
}

/**
 * Authenticates a registry identity at `at`: the issuer's key is one of
 * `roots`, the issuer is self-signed, the certificate fits the signing
 * profile (an end entity usable only for digital signatures and code
 * signing, signed with ECDSA P-256 over SHA-256, valid for at most ten
 * minutes inside the issuer's window, with an empty subject and exactly one
 * critical URI SAN naming a canonical registry ID), its key is not a root
 * key, and it chains to the issuer at `at`, an authority whose extended key
 * usage, when it carries one, allows code signing. `validateRegistryID` is
 * applied to the registry ID.
 */
export async function verifySigningCertificate(
  certificateDer: Uint8Array,
  issuerDer: Uint8Array,
  roots: readonly PinnedKey[],
  at: Date,
  validateRegistryID: (registryID: string) => void,
): Promise<RegistryCertificate> {
  if (
    !Number.isFinite(at.getTime()) ||
    certificateDer.length === 0 ||
    certificateDer.length > MAX_CERTIFICATE_SIZE ||
    issuerDer.length === 0 ||
    issuerDer.length > MAX_CERTIFICATE_SIZE
  ) {
    throw new Error("signing certificate requires a time and bounded certificate bytes");
  }
  const certificate = parseCertificate(certificateDer);
  const issuer = parseCertificate(issuerDer);
  const trusted = roots.map((k) => k.hint);
  if (!trusted.includes(await keyHint(issuer.spki))) throw new Error("untrusted registry root");
  if (!(await verifyCertificateSignature(issuer, issuer.spki))) throw new Error("invalid registry root certificate");

  const constraints = basicConstraints(certificate);
  const usage = keyUsage(certificate);
  if (
    constraints === undefined ||
    constraints.ca ||
    usage === undefined ||
    !usage[KEY_USAGE_DIGITAL_SIGNATURE] ||
    usage.some((set, bit) => set && bit !== KEY_USAGE_DIGITAL_SIGNATURE) ||
    !codeSigningOnly(certificate) ||
    certificate.signatureAlgorithm !== "ecdsa-p256-sha256" ||
    certificate.notAfter.getTime() - certificate.notBefore.getTime() > CERTIFICATE_VALIDITY_MS ||
    certificate.notBefore.getTime() < issuer.notBefore.getTime() ||
    certificate.notAfter.getTime() > issuer.notAfter.getTime() ||
    !bytesEqual(certificate.subject, EMPTY_NAME) ||
    extension(certificate, OID_FULCIO_ISSUER_V1) !== undefined ||
    extension(certificate, OID_FULCIO_ISSUER_V2) !== undefined
  ) {
    throw new Error("invalid config signing certificate profile");
  }
  const registryID = registryIDOf(certificate);
  validateRegistryID(registryID);
  if (trusted.includes(await keyHint(certificate.spki))) throw new Error("registry root cannot serve as a config signing key");
  const unsupported = unsupportedCriticalExtension(certificate);
  if (unsupported !== undefined) throw new Error(`config signing certificate carries unsupported critical extension ${unsupported}`);
  if (!canIssueCertificates(issuer)) throw new Error("registry root is not a certificate authority");
  if (!allowsCodeSigning(issuer)) throw new Error("registry root's extended key usage does not allow code signing");
  try {
    await verifyChain([certificate, issuer], [issuer], at);
  } catch (err) {
    throw new Error(`verifying config signing certificate: ${err instanceof Error ? err.message : String(err)}`);
  }
  return { certificate, issuer, registryID };
}

/** The extended key usage purposes, or undefined when the extension is absent or malformed. */
function extendedKeyUsage(cert: Certificate): string[] | undefined {
  const ext = extension(cert, OID_EXT_KEY_USAGE);
  if (ext === undefined) return undefined;
  try {
    return expectSequence(decode(ext.value), "ExtKeyUsage").map(oid);
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) return undefined;
    throw err;
  }
}

/** Whether the extended key usage names exactly code signing. */
function codeSigningOnly(cert: Certificate): boolean {
  const purposes = extendedKeyUsage(cert);
  return purposes !== undefined && purposes.length === 1 && purposes[0] === OID_KP_CODE_SIGNING;
}

/**
 * Whether an issuer may stand above a code-signing certificate: it carries
 * no extended key usage, or one naming code signing or any purpose. A
 * malformed extension permits nothing.
 */
function allowsCodeSigning(cert: Certificate): boolean {
  if (extension(cert, OID_EXT_KEY_USAGE) === undefined) return true;
  const purposes = extendedKeyUsage(cert);
  return purposes !== undefined && purposes.some((p) => p === OID_KP_CODE_SIGNING || p === OID_KP_ANY);
}

/**
 * The registry ID: the subject alternative name extension must be critical
 * and hold exactly one GeneralName, a uniformResourceIdentifier.
 */
function registryIDOf(cert: Certificate): string {
  const ext = extension(cert, OID_SUBJECT_ALT_NAME);
  if (ext === undefined || !ext.critical) throw new Error("registry identity requires exactly one critical URI SAN");
  let names;
  try {
    names = expectSequence(decode(ext.value), "GeneralNames");
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error("registry identity requires exactly one critical URI SAN");
    throw err;
  }
  const [name] = names;
  if (names.length !== 1 || name.tagClass !== CLASS_CONTEXT || name.tag !== URI_GENERAL_NAME_TAG || name.constructed) {
    throw new Error("registry identity requires exactly one critical URI SAN");
  }
  let registryID = "";
  for (const b of name.value) {
    if (b < 0x20 || b > 0x7e) throw new Error("registry identity requires exactly one critical URI SAN");
    registryID += String.fromCharCode(b);
  }
  return registryID;
}
