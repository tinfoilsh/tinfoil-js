/**
 * RFC 3161 timestamps from the trusted root's timestamp authorities, and the canonical input they sign.
 *
 * A response is read from the strict DER tree: the status, then the CMS
 * SignedData token, its single SignerInfo, and the TSTInfo it encapsulates.
 * The signature covers the signed attributes, which commit to the TSTInfo
 * through the message-digest attribute. The signer is identified by issuer
 * and serial number and must be the signing certificate of some authority in
 * the root; certificates embedded in the token are never trusted.
 */
import { concat, sha256, toHex, utf8 } from "../bytes.js";
import { canonicalize, type JsonValue } from "../json/index.js";
import {
  basicConstraints,
  bytesEqual,
  canSignData,
  expectSequence,
  extension,
  isContext,
  isUniversal,
  parseCertificate,
  verifyChain,
  X509Error,
  type Certificate,
} from "../x509/certificate.js";
import { children, decode, DerError, ecdsaSignatureToRaw, integer, oid, TAG, time, type DerElement } from "../x509/der.js";
import { IN_TOTO_PAYLOAD_TYPE } from "./bundle.js";
import type { CertificateAuthority, TrustedRoot } from "./trusted-root.js";

/** The policy OID a Sigstore timestamp authority must state. */
export const SIGSTORE_TIMESTAMP_POLICY = "1.3.6.1.4.1.57264.2";
export const MAX_TIMESTAMP_SIZE = 64 << 10;
export const MAX_STATEMENT_SIZE = 128 << 10;

/** The only PKIStatus accepted; grantedWithMods (1) and every other status reject. */
export const STATUS_GRANTED = 0n;

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12";
const OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
const OID_SHA1 = "1.3.14.3.2.26";
const DIRECTORY_NAME_TAG = 4;
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_SHA384 = "2.16.840.1.101.3.4.2.2";
const OID_SHA512 = "2.16.840.1.101.3.4.2.3";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4";
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
const OID_RSA_SHA256 = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384 = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512 = "1.2.840.113549.1.1.13";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_P256 = "1.2.840.10045.3.1.7";
const OID_P384 = "1.3.132.0.34";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
const OID_KP_ANY = "2.5.29.37.0";

type HashName = "SHA-256" | "SHA-384" | "SHA-512";

const HASHES: Readonly<Record<string, HashName>> = {
  [OID_SHA256]: "SHA-256",
  [OID_SHA384]: "SHA-384",
  [OID_SHA512]: "SHA-512",
};

/**
 * The bytes a timestamp covers for a statement: `domain` followed by the
 * RFC 8785 canonical form of `core`.
 */
export function timestampInput(domain: string, core: JsonValue): Uint8Array {
  return concat(utf8(domain), canonicalize(core));
}

/**
 * The DSSE pre-authentication encoding of a payload:
 * "DSSEv1" SP len(type) SP type SP len(payload) SP payload, lengths in bytes as decimal ASCII.
 */
export function preAuthEncoding(payloadType: string, payload: Uint8Array): Uint8Array {
  const type = utf8(payloadType);
  return concat(utf8(`DSSEv1 ${type.length} `), type, utf8(` ${payload.length} `), payload);
}

/** "sha256:" + hex SHA-256 of the DSSE pre-authentication encoding of an in-toto payload. */
export async function endorsementReference(payload: Uint8Array): Promise<string> {
  return "sha256:" + toHex(await sha256(preAuthEncoding(IN_TOTO_PAYLOAD_TYPE, payload)));
}

/** What a timestamp response states, read before any authority is trusted. */
export interface TimestampResponse {
  readonly status: bigint;
  readonly policy: string;
  readonly genTime: Date;
  readonly serialNumber: bigint;
  /** The message imprint's hash algorithm OID and digest. */
  readonly imprintAlgorithm: string;
  readonly imprint: Uint8Array;
  /** The DER Name and serial number that identify the signing certificate. */
  readonly signerIssuer: Uint8Array;
  readonly signerSerial: bigint;
  /** The DER TSTInfo, the content the message-digest attribute commits to. */
  readonly tstInfo: Uint8Array;
  /** The signed attributes as the DER SET the signature covers. */
  readonly signedAttributes: Uint8Array;
  /** The message-digest attribute's value. */
  readonly messageDigest: Uint8Array;
  readonly signingCertificates: readonly { v2: boolean; value: DerElement }[];
  /** The signer's digest algorithm, which hashes the TSTInfo. */
  readonly digestAlgorithm: HashName;
  readonly signatureAlgorithm: string;
  readonly signature: Uint8Array;
}

/**
 * Parses a DER TimeStampResp: the status must be an unqualified grant, the
 * token a CMS SignedData with one SignerInfo identified by issuer and serial
 * number, carrying content-type and message-digest attributes, and
 * encapsulating a TSTInfo.
 */
export function parseTimestampResponse(response: Uint8Array): TimestampResponse {
  if (response.length === 0 || response.length > MAX_TIMESTAMP_SIZE) {
    throw new Error("timestamp response size is outside allowed bounds");
  }
  try {
    return parseResponse(response);
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`timestamp response: ${err.message}`);
    throw err;
  }
}

/**
 * Verifies a timestamp response over `input`: the message imprint is SHA-256
 * of `input`, the policy OID is the Sigstore one, and some authority in
 * `root` signed it and was valid at the stated time. Returns that time.
 */
export async function verifyTimestamp(root: TrustedRoot, response: Uint8Array, input: Uint8Array): Promise<Date> {
  if (input.length === 0 || input.length > MAX_STATEMENT_SIZE) {
    throw new Error("timestamp input size is outside allowed bounds");
  }
  const ts = parseTimestampResponse(response);
  if (ts.imprintAlgorithm !== OID_SHA256 || !bytesEqual(ts.imprint, await sha256(input))) {
    throw new Error("timestamp response does not match the input");
  }
  if (ts.policy !== SIGSTORE_TIMESTAMP_POLICY) {
    throw new Error(`unexpected timestamp policy ${ts.policy}`);
  }
  return verifyParsedTimestamp(root, ts);
}

/** Authenticates a bundle-signature timestamp without imposing an approval policy OID. */
export async function verifySignatureTimestamp(root: TrustedRoot, response: Uint8Array, signature: Uint8Array): Promise<Date> {
  const ts = parseTimestampResponse(response);
  const hash = HASHES[ts.imprintAlgorithm];
  if (hash === undefined || !bytesEqual(ts.imprint, new Uint8Array(await crypto.subtle.digest(hash, asBuffer(signature))))) {
    throw new Error("timestamp response does not match the signature");
  }
  return verifyParsedTimestamp(root, ts);
}

async function verifyParsedTimestamp(root: TrustedRoot, ts: TimestampResponse): Promise<Date> {
  const digest = new Uint8Array(await crypto.subtle.digest(ts.digestAlgorithm, asBuffer(ts.tstInfo)));
  if (!bytesEqual(digest, ts.messageDigest)) {
    throw new Error("timestamp signed attributes do not commit to the TSTInfo");
  }
  const failures: string[] = [];
  for (let i = 0; i < root.timestampAuthorities.length; i++) {
    try {
      await verifyUnderAuthority(root.timestampAuthorities[i], ts);
      return ts.genTime;
    } catch (err) {
      failures.push(`authority ${i}: ${message(err)}`);
    }
  }
  throw new Error(`no trusted timestamp authority authenticated the response${failures.length === 0 ? "" : ` (${failures.join("; ")})`}`);
}

// ---------------------------------------------------------------- response parsing

function parseResponse(response: Uint8Array): TimestampResponse {
  const resp = expectSequence(decode(response), "TimeStampResp");
  if (resp.length < 1 || resp.length > 2) throw new Error("TimeStampResp must hold a status and an optional token");
  const statusInfo = expectSequence(resp[0], "PKIStatusInfo");
  if (statusInfo.length === 0) throw new Error("PKIStatusInfo has no status");
  const status = integer(statusInfo[0]);
  // Only an unqualified grant is accepted; a grant with modifications is a
  // different response than the one requested.
  if (status !== STATUS_GRANTED) {
    throw new Error(`timestamp request was not granted (status ${status})`);
  }
  if (resp.length !== 2) throw new Error("granted timestamp response has no token");

  const contentInfo = expectSequence(resp[1], "TimeStampToken");
  if (contentInfo.length !== 2 || oid(contentInfo[0]) !== OID_SIGNED_DATA) {
    throw new Error("TimeStampToken must be a SignedData ContentInfo");
  }
  const signedData = expectSequence(explicit(contentInfo[1], 0, "SignedData content"), "SignedData");
  if (signedData.length < 4) throw new Error("SignedData is missing required fields");
  integer(signedData[0]);
  if (!isUniversal(signedData[1], TAG.SET)) throw new Error("SignedData digestAlgorithms must be a SET");
  const encap = expectSequence(signedData[2], "EncapsulatedContentInfo");
  if (encap.length !== 2 || oid(encap[0]) !== OID_TST_INFO) {
    throw new Error("SignedData must encapsulate a TSTInfo");
  }
  const eContent = explicit(encap[1], 0, "eContent");
  if (!isUniversal(eContent, TAG.OCTET_STRING)) throw new Error("eContent must be an OCTET STRING");
  const tstInfo = eContent.value;
  // Certificates ([0]) and revocation lists ([1]) are optional and unused: trust comes from the root.
  let i = 3;
  while (i < signedData.length && (isContext(signedData[i], 0) || isContext(signedData[i], 1))) i++;
  if (i !== signedData.length - 1 || !isUniversal(signedData[i], TAG.SET)) {
    throw new Error("SignedData must end in its signerInfos SET");
  }
  const signerInfos = children(signedData[i]);
  if (signerInfos.length !== 1) throw new Error(`SignedData must have exactly one signer, got ${signerInfos.length}`);

  const signer = parseSignerInfo(signerInfos[0]);
  const info = parseTstInfo(tstInfo);
  return { status, ...info, ...signer, tstInfo };
}

interface SignerInfo {
  readonly signerIssuer: Uint8Array;
  readonly signerSerial: bigint;
  readonly signedAttributes: Uint8Array;
  readonly messageDigest: Uint8Array;
  readonly signingCertificates: readonly { v2: boolean; value: DerElement }[];
  readonly digestAlgorithm: HashName;
  readonly signatureAlgorithm: string;
  readonly signature: Uint8Array;
}

function parseSignerInfo(el: DerElement): SignerInfo {
  const fields = expectSequence(el, "SignerInfo");
  if (fields.length < 6 || fields.length > 7) throw new Error("SignerInfo is missing required fields");
  if (integer(fields[0]) !== 1n) throw new Error("SignerInfo must identify its signer by issuer and serial number");
  const sid = expectSequence(fields[1], "IssuerAndSerialNumber");
  if (sid.length !== 2) throw new Error("IssuerAndSerialNumber must hold a Name and a serial number");
  expectSequence(sid[0], "issuer Name");
  const digestAlgorithm = hashAlgorithm(fields[2], "SignerInfo digestAlgorithm");
  const attrs = fields[3];
  if (!isContext(attrs, 0) || !attrs.constructed) throw new Error("SignerInfo must carry signed attributes");
  const { contentType, messageDigest, signingCertificates } = parseSignedAttributes(attrs);
  if (contentType !== OID_TST_INFO) throw new Error("signed content-type attribute is not TSTInfo");
  const signatureAlgorithm = parseSignatureAlgorithm(fields[4]);
  if (!isUniversal(fields[5], TAG.OCTET_STRING)) throw new Error("SignerInfo signature must be an OCTET STRING");
  if (fields.length === 7 && !isContext(fields[6], 1)) throw new Error("unexpected field in SignerInfo");
  // The signature covers the attributes encoded as a SET rather than under their implicit tag.
  const signedAttributes = new Uint8Array(attrs.raw);
  signedAttributes[0] = 0x31;
  return {
    signerIssuer: sid[0].raw,
    signerSerial: integer(sid[1]),
    signedAttributes,
    messageDigest,
    signingCertificates,
    digestAlgorithm,
    signatureAlgorithm,
    signature: fields[5].value,
  };
}

/** The content-type and message-digest attributes; each must appear exactly once with one value. */
function parseSignedAttributes(attrs: DerElement): { contentType: string; messageDigest: Uint8Array; signingCertificates: { v2: boolean; value: DerElement }[] } {
  let contentType: string | undefined;
  let messageDigest: Uint8Array | undefined;
  const signingCertificates: { v2: boolean; value: DerElement }[] = [];
  const seen = new Set<string>();
  for (const attr of children(attrs)) {
    const parts = expectSequence(attr, "Attribute");
    if (parts.length !== 2 || !isUniversal(parts[1], TAG.SET)) throw new Error("Attribute must hold a type and a SET of values");
    const type = oid(parts[0]);
    if (![OID_CONTENT_TYPE, OID_MESSAGE_DIGEST, OID_SIGNING_CERTIFICATE, OID_SIGNING_CERTIFICATE_V2].includes(type)) continue;
    if (seen.has(type)) throw new Error(`duplicate timestamp signed attribute ${type}`);
    seen.add(type);
    const values = children(parts[1]);
    if (values.length !== 1) throw new Error(`attribute ${type} must have exactly one value`);
    if (type === OID_CONTENT_TYPE) {
      if (contentType !== undefined) throw new Error("duplicate content-type attribute");
      contentType = oid(values[0]);
    } else if (type === OID_MESSAGE_DIGEST) {
      if (messageDigest !== undefined) throw new Error("duplicate message-digest attribute");
      if (!isUniversal(values[0], TAG.OCTET_STRING)) throw new Error("message-digest attribute must be an OCTET STRING");
      messageDigest = values[0].value;
    } else {
      signingCertificates.push({ v2: type === OID_SIGNING_CERTIFICATE_V2, value: values[0] });
    }
  }
  if (contentType === undefined) throw new Error("signed attributes lack content-type");
  if (messageDigest === undefined) throw new Error("signed attributes lack message-digest");
  if (signingCertificates.length === 0) throw new Error("timestamp lacks a signing-certificate attribute");
  return { contentType, messageDigest, signingCertificates };
}

interface TstInfo {
  readonly policy: string;
  readonly genTime: Date;
  readonly serialNumber: bigint;
  readonly imprintAlgorithm: string;
  readonly imprint: Uint8Array;
}

function parseTstInfo(der: Uint8Array): TstInfo {
  const fields = expectSequence(decode(der), "TSTInfo");
  if (fields.length < 5) throw new Error("TSTInfo is missing required fields");
  if (integer(fields[0]) !== 1n) throw new Error("unsupported TSTInfo version");
  const policy = oid(fields[1]);
  const imprint = expectSequence(fields[2], "MessageImprint");
  if (imprint.length !== 2 || !isUniversal(imprint[1], TAG.OCTET_STRING)) {
    throw new Error("MessageImprint must hold an algorithm and a digest");
  }
  const algorithm = expectSequence(imprint[0], "MessageImprint hashAlgorithm");
  if (algorithm.length === 0 || algorithm.length > 2 || (algorithm[1] !== undefined && !isUniversal(algorithm[1], TAG.NULL))) {
    throw new Error("hash AlgorithmIdentifier must hold an OID and optional NULL");
  }
  const serialNumber = integer(fields[3]);
  if (!isUniversal(fields[4], TAG.GENERALIZED_TIME)) throw new Error("TSTInfo genTime must be a GeneralizedTime");
  // genTime may state fractional seconds; the authority decides its precision.
  const genTime = time(fields[4], { fractionalSeconds: true });
  return { policy, genTime, serialNumber, imprintAlgorithm: oid(algorithm[0]), imprint: imprint[1].value };
}

/** An AlgorithmIdentifier naming a supported hash, with optional NULL parameters. */
function hashAlgorithm(algId: DerElement, what: string): HashName {
  const parts = expectSequence(algId, what);
  if (parts.length === 0 || parts.length > 2 || (parts[1] !== undefined && !isUniversal(parts[1], TAG.NULL))) {
    throw new Error(`${what} must hold an OID and optional NULL`);
  }
  const id = oid(parts[0]);
  const hash = HASHES[id];
  if (hash === undefined) throw new Error(`unsupported digest algorithm ${id}`);
  return hash;
}

/** The signature AlgorithmIdentifier's OID, limited to the ECDSA and RSA PKCS#1 v1.5 algorithms supported here. */
function parseSignatureAlgorithm(algId: DerElement): string {
  const parts = expectSequence(algId, "SignerInfo signatureAlgorithm");
  if (parts.length === 0 || parts.length > 2) throw new Error("signature AlgorithmIdentifier must hold an OID and optional parameters");
  const id = oid(parts[0]);
  switch (id) {
    case OID_ECDSA_SHA256:
    case OID_ECDSA_SHA384:
    case OID_ECDSA_SHA512:
      if (parts[1] !== undefined) throw new Error("ECDSA signature algorithm takes no parameters");
      return id;
    case OID_RSA_ENCRYPTION:
    case OID_RSA_SHA256:
    case OID_RSA_SHA384:
    case OID_RSA_SHA512:
      if (parts[1] !== undefined && !isUniversal(parts[1], TAG.NULL)) throw new Error("RSA signature algorithm parameters must be NULL");
      return id;
    default:
      throw new Error(`unsupported signature algorithm ${id}`);
  }
}

/** The one element inside an EXPLICIT context tag. */
function explicit(el: DerElement, tag: number, what: string): DerElement {
  if (!isContext(el, tag) || !el.constructed) throw new Error(`${what} must be tagged [${tag}]`);
  const inner = children(el);
  if (inner.length !== 1) throw new Error(`${what} must wrap one element`);
  return inner[0];
}

// ---------------------------------------------------------------- authority verification

/**
 * Checks one authority: its window contains genTime, its signing certificate
 * is the token's signer, that certificate is an end entity whose key usage
 * permits signing and that is restricted to timestamping, its chain verifies
 * at genTime, and the signature verifies under its key.
 */
async function verifyUnderAuthority(authority: CertificateAuthority, ts: TimestampResponse): Promise<void> {
  const at = ts.genTime.getTime();
  if (at < authority.validFrom.getTime() || (authority.validTo !== undefined && at > authority.validTo.getTime())) {
    throw new Error(`not valid at ${ts.genTime.toISOString()}`);
  }
  const chain = authority.chainDer.map(parseCertificate).reverse();
  const leaf = chain[0];
  if (!bytesEqual(leaf.issuer, ts.signerIssuer) || leaf.serialNumber !== ts.signerSerial) {
    throw new Error("the token's signer is not the authority's signing certificate");
  }
  if (basicConstraints(leaf)?.ca === true) throw new Error("the signing certificate is a certificate authority");
  if (!canSignData(leaf)) throw new Error("the signing certificate's key usage does not permit signing");
  await checkSigningCertificates(ts, leaf);
  checkTimestampingUsage(chain);
  await verifyChain(chain, [chain[chain.length - 1]], ts.genTime);
  if (!(await verifySignature(ts, leaf.spki))) throw new Error("the timestamp signature does not verify");
}

async function checkSigningCertificates(ts: TimestampResponse, signer: Certificate): Promise<void> {
  for (const binding of ts.signingCertificates) {
    const value = expectSequence(binding.value, "SigningCertificate");
    if (value.length < 1 || value.length > 2) throw new Error("invalid signing-certificate attribute");
    const certs = expectSequence(value[0], "SigningCertificate certs");
    if (certs.length === 0) throw new Error("signing-certificate attribute has no certificates");
    const fields = expectSequence(certs[0], "ESSCertID");
    let hash: string = binding.v2 ? "SHA-256" : "SHA-1";
    if (binding.v2 && fields.length > 0 && isUniversal(fields[0], TAG.SEQUENCE)) {
      const algorithm = expectSequence(fields.shift()!, "ESSCertIDv2 hashAlgorithm");
      if (algorithm.length < 1 || algorithm.length > 2 || (algorithm[1] !== undefined && !isUniversal(algorithm[1], TAG.NULL))) {
        throw new Error("invalid certificate hash algorithm parameters");
      }
      const id = oid(algorithm[0]);
      hash = id === OID_SHA1 ? "SHA-1" : HASHES[id];
      if (hash === undefined) throw new Error(`unsupported certificate hash algorithm ${id}`);
    }
    if (fields.length < 1 || fields.length > 2 || !isUniversal(fields[0], TAG.OCTET_STRING)) {
      throw new Error("invalid timestamp certificate identifier");
    }
    const digest = new Uint8Array(await crypto.subtle.digest(hash, asBuffer(signer.raw)));
    if (!bytesEqual(fields[0].value, digest)) throw new Error("timestamp certificate hash does not match signer");
    if (fields.length === 2) {
      const issuerSerial = expectSequence(fields[1], "IssuerSerial");
      if (issuerSerial.length !== 2 || integer(issuerSerial[1]) !== signer.serialNumber) {
        throw new Error("timestamp certificate serial does not match signer");
      }
      const names = expectSequence(issuerSerial[0], "GeneralNames");
      if (!names.some((name) => isContext(name, DIRECTORY_NAME_TAG) && bytesEqual(explicit(name, DIRECTORY_NAME_TAG, "directoryName").raw, signer.issuer))) {
        throw new Error("timestamp certificate issuer does not match signer");
      }
    }
  }
}

/**
 * The signing certificate must carry a critical extended key usage naming
 * only timestamping; an intermediate with an extended key usage must allow
 * timestamping or any usage.
 */
function checkTimestampingUsage(chain: readonly Certificate[]): void {
  const leafUsage = extendedKeyUsage(chain[0]);
  if (leafUsage === undefined) throw new Error("the signing certificate has no extended key usage");
  if (!leafUsage.critical || leafUsage.purposes.length !== 1 || leafUsage.purposes[0] !== OID_KP_TIMESTAMPING) {
    throw new Error("the signing certificate's extended key usage must be critical and name only timestamping");
  }
  for (let i = 1; i + 1 < chain.length; i++) {
    const usage = extendedKeyUsage(chain[i]);
    if (usage !== undefined && !usage.purposes.some((p) => p === OID_KP_TIMESTAMPING || p === OID_KP_ANY)) {
      throw new Error(`intermediate certificate ${i} does not allow timestamping`);
    }
  }
}

function extendedKeyUsage(cert: Certificate): { critical: boolean; purposes: string[] } | undefined {
  const ext = extension(cert, OID_EXT_KEY_USAGE);
  if (ext === undefined) return undefined;
  try {
    return { critical: ext.critical, purposes: expectSequence(decode(ext.value), "ExtKeyUsage").map(oid) };
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`extended key usage: ${err.message}`);
    throw err;
  }
}

/** Verifies the token signature over the signed attributes with the key in `spki`; false for any mismatch or failure. */
async function verifySignature(ts: TimestampResponse, spki: Uint8Array): Promise<boolean> {
  const data = asBuffer(ts.signedAttributes);
  try {
    switch (ts.signatureAlgorithm) {
      case OID_ECDSA_SHA256:
      case OID_ECDSA_SHA384:
      case OID_ECDSA_SHA512: {
        const hash: HashName = ts.signatureAlgorithm === OID_ECDSA_SHA256 ? "SHA-256" : ts.signatureAlgorithm === OID_ECDSA_SHA384 ? "SHA-384" : "SHA-512";
        if (hash !== ts.digestAlgorithm) return false;
        const curve = ecCurve(spki);
        if (curve === undefined) return false;
        const raw = ecdsaSignatureToRaw(ts.signature, curve === "P-256" ? 32 : 48);
        const key = await crypto.subtle.importKey("spki", asBuffer(spki), { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
        return await crypto.subtle.verify({ name: "ECDSA", hash }, key, asBuffer(raw), data);
      }
      default: {
        // RSA PKCS#1 v1.5: the bare rsaEncryption identifier takes its hash from the digest algorithm.
        const hash: HashName | undefined =
          ts.signatureAlgorithm === OID_RSA_ENCRYPTION
            ? ts.digestAlgorithm
            : ts.signatureAlgorithm === OID_RSA_SHA256
              ? "SHA-256"
              : ts.signatureAlgorithm === OID_RSA_SHA384
                ? "SHA-384"
                : ts.signatureAlgorithm === OID_RSA_SHA512
                  ? "SHA-512"
                  : undefined;
        if (hash === undefined || hash !== ts.digestAlgorithm) return false;
        const key = await crypto.subtle.importKey("spki", asBuffer(spki), { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
        return await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, asBuffer(ts.signature), data);
      }
    }
  } catch {
    // A malformed signature, or a key the algorithm cannot use: the signature does not verify.
    return false;
  }
}

/** The named curve of an EC SubjectPublicKeyInfo, or undefined for any other key. */
function ecCurve(spki: Uint8Array): "P-256" | "P-384" | undefined {
  try {
    const parts = expectSequence(decode(spki), "SubjectPublicKeyInfo");
    if (parts.length !== 2) return undefined;
    const alg = expectSequence(parts[0], "key AlgorithmIdentifier");
    if (alg.length !== 2 || oid(alg[0]) !== OID_EC_PUBLIC_KEY) return undefined;
    const curve = oid(alg[1]);
    return curve === OID_P256 ? "P-256" : curve === OID_P384 ? "P-384" : undefined;
  } catch {
    return undefined;
  }
}

function asBuffer(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return b as Uint8Array<ArrayBuffer>;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
