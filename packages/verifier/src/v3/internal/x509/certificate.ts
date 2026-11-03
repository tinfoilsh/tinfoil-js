/**
 * X.509 certificates: strict parsing, signature verification and the extensions the verifier reads.
 *
 * The certificate is read from the strict DER tree rather than through the
 * sigstore certificate wrapper: that wrapper returns names as content bytes
 * rather than whole DER Names, assumes a version field is present, infers the
 * RSA-PSS salt length from the hash instead of the signature parameters, and
 * refuses keys labelled id-RSASSA-PSS. Signatures go straight to WebCrypto.
 */
import { encodeLength } from "@freedomofpress/crypto-browser";
import { concat, toHex } from "../bytes.js";
import {
  bitString,
  boolean,
  children,
  CLASS_CONTEXT,
  CLASS_UNIVERSAL,
  decode,
  DerError,
  ecdsaSignatureToRaw,
  integer,
  oid,
  TAG,
  time,
  type DerElement,
} from "./der.js";

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

/** Thrown when a certificate or revocation list is malformed, unsupported, or fails verification. */
export class X509Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "X509Error";
  }
}

export const OID_BASIC_CONSTRAINTS = "2.5.29.19";
export const OID_KEY_USAGE = "2.5.29.15";
const OID_COMMON_NAME = "2.5.4.3";

const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const OID_RSA_PSS = "1.2.840.113549.1.1.10";
const OID_RSA_SHA256 = "1.2.840.113549.1.1.11";
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
const OID_MGF1 = "1.2.840.113549.1.1.8";
const OID_SHA384 = "2.16.840.1.101.3.4.2.2";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_P256 = "1.2.840.10045.3.1.7";
const OID_P384 = "1.3.132.0.34";

/** KeyUsage bit positions (bit 0 is the most significant bit of the first byte). */
const KEY_USAGE_KEY_CERT_SIGN = 5;
const KEY_USAGE_CRL_SIGN = 6;

// ---------------------------------------------------------------- DER tree helpers

export function isUniversal(e: DerElement, tag: number): boolean {
  return e.tagClass === CLASS_UNIVERSAL && e.tag === tag;
}

export function isContext(e: DerElement, tag: number): boolean {
  return e.tagClass === CLASS_CONTEXT && e.tag === tag;
}

export function expectSequence(e: DerElement, what: string): DerElement[] {
  if (!isUniversal(e, TAG.SEQUENCE)) throw new X509Error(`${what} must be a SEQUENCE`);
  return children(e);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Re-raises DER violations as X509Error with context; other errors pass through. */
export function withContext<T>(what: string, f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof DerError) throw new X509Error(`${what}: ${e.message}`);
    throw e;
  }
}

/**
 * Interprets an AlgorithmIdentifier as one of the supported signature
 * algorithms. RSA-PSS is accepted only with SHA-384, MGF1 with SHA-384, a
 * 48-byte salt and the default trailer field.
 */
export function signatureAlgorithm(algId: DerElement): SignatureAlgorithm {
  const parts = expectSequence(algId, "AlgorithmIdentifier");
  if (parts.length === 0 || parts.length > 2) throw new X509Error("AlgorithmIdentifier must hold an OID and optional parameters");
  const id = oid(parts[0]);
  const params = parts[1];
  switch (id) {
    case OID_ECDSA_SHA256:
    case OID_ECDSA_SHA384:
      if (params !== undefined) throw new X509Error("ECDSA signature algorithm takes no parameters");
      return id === OID_ECDSA_SHA256 ? "ecdsa-p256-sha256" : "ecdsa-p384-sha384";
    case OID_RSA_SHA256:
      if (params !== undefined && !(isUniversal(params, TAG.NULL))) {
        throw new X509Error("RSA PKCS#1 signature algorithm parameters must be NULL");
      }
      return "rsa-pkcs1-sha256";
    case OID_RSA_PSS:
      if (params === undefined) throw new X509Error("RSA-PSS signature algorithm requires parameters");
      checkPssParams(params);
      return "rsa-pss-sha384";
    default:
      throw new X509Error(`unsupported signature algorithm ${id}`);
  }
}

function checkPssParams(params: DerElement): void {
  const fields = expectSequence(params, "RSA-PSS parameters");
  let hash: string | undefined;
  let mgfHash: string | undefined;
  let salt: bigint | undefined;
  let trailer: bigint | undefined;
  for (const f of fields) {
    if (f.tagClass !== CLASS_CONTEXT || !f.constructed) throw new X509Error("RSA-PSS parameter is not tagged");
    const inner = children(f);
    if (inner.length !== 1) throw new X509Error("RSA-PSS parameter must wrap one value");
    switch (f.tag) {
      case 0:
        hash = hashOid(inner[0]);
        break;
      case 1: {
        const mgf = expectSequence(inner[0], "RSA-PSS mask generation function");
        if (mgf.length !== 2 || oid(mgf[0]) !== OID_MGF1) throw new X509Error("RSA-PSS mask generation function must be MGF1");
        mgfHash = hashOid(mgf[1]);
        break;
      }
      case 2:
        salt = integer(inner[0]);
        break;
      case 3:
        trailer = integer(inner[0]);
        break;
      default:
        throw new X509Error("unknown RSA-PSS parameter");
    }
  }
  if (hash !== OID_SHA384 || mgfHash !== OID_SHA384 || salt !== 48n) {
    throw new X509Error("RSA-PSS is supported only with SHA-384, MGF1-SHA-384 and a 48-byte salt");
  }
  if (trailer !== undefined && trailer !== 1n) throw new X509Error("RSA-PSS trailer field must be 1");
}

function hashOid(algId: DerElement): string {
  const parts = expectSequence(algId, "hash AlgorithmIdentifier");
  if (parts.length === 0 || parts.length > 2) throw new X509Error("hash AlgorithmIdentifier must hold an OID and optional NULL");
  if (parts[1] !== undefined && !isUniversal(parts[1], TAG.NULL)) throw new X509Error("hash parameters must be NULL");
  return oid(parts[0]);
}

/** The subject's common name, decoded from the Name's first CN attribute when it is a string type. */
function commonName(name: DerElement): string | undefined {
  for (const rdn of expectSequence(name, "Name")) {
    if (!isUniversal(rdn, TAG.SET)) throw new X509Error("Name must hold SETs of attributes");
    for (const atv of children(rdn)) {
      const parts = expectSequence(atv, "attribute");
      if (parts.length !== 2) throw new X509Error("attribute must be a type and a value");
      if (oid(parts[0]) !== OID_COMMON_NAME) continue;
      const v = parts[1];
      if (isUniversal(v, TAG.UTF8_STRING) || isUniversal(v, TAG.PRINTABLE_STRING) || isUniversal(v, TAG.IA5_STRING)) {
        try {
          return new TextDecoder("utf-8", { fatal: true }).decode(v.value);
        } catch {
          throw new X509Error("common name is not valid UTF-8");
        }
      }
      return undefined;
    }
  }
  return undefined;
}

function parseExtensions(wrapper: DerElement): Extension[] {
  const inner = children(wrapper);
  if (inner.length !== 1) throw new X509Error("extensions must wrap one SEQUENCE");
  const out: Extension[] = [];
  const seen = new Set<string>();
  for (const ext of expectSequence(inner[0], "extensions")) {
    const parts = expectSequence(ext, "extension");
    if (parts.length < 2 || parts.length > 3) throw new X509Error("extension must hold an OID, optional critical flag and value");
    const id = oid(parts[0]);
    let critical = false;
    if (parts.length === 3) {
      critical = boolean(parts[1]);
      // DER omits a value equal to its default, so an explicit FALSE is not DER.
      if (!critical) throw new X509Error("extension encodes the default critical value");
    }
    const value = parts[parts.length - 1];
    if (!isUniversal(value, TAG.OCTET_STRING)) throw new X509Error("extension value must be an OCTET STRING");
    if (seen.has(id)) throw new X509Error(`duplicate extension ${id}`);
    seen.add(id);
    out.push({ oid: id, critical, value: value.value });
  }
  return out;
}

/** Parses a DER certificate. Unknown critical extensions do not reject here; callers decide. */
export function parseCertificate(der: Uint8Array): Certificate {
  return withContext("certificate", () => {
    const top = expectSequence(decode(der), "Certificate");
    if (top.length !== 3) throw new X509Error("Certificate must hold tbsCertificate, signatureAlgorithm and signatureValue");
    const [tbsEl, outerAlg, sigEl] = top;
    const tbs = expectSequence(tbsEl, "TBSCertificate");
    let i = 0;
    let version = 0n;
    if (tbs.length > 0 && isContext(tbs[0], 0)) {
      if (!tbs[0].constructed) throw new X509Error("version must be explicitly tagged");
      const v = children(tbs[0]);
      if (v.length !== 1) throw new X509Error("version must wrap one INTEGER");
      version = integer(v[0]);
      if (version > 2n) throw new X509Error(`unsupported certificate version ${version + 1n}`);
      if (version === 0n) throw new X509Error("version 1 must be encoded by omitting the version field");
      i = 1;
    }
    if (tbs.length < i + 6) throw new X509Error("TBSCertificate is missing required fields");
    const serialNumber = integer(tbs[i]);
    const innerAlg = tbs[i + 1];
    const issuerEl = tbs[i + 2];
    const validity = expectSequence(tbs[i + 3], "Validity");
    const subjectEl = tbs[i + 4];
    const spkiEl = tbs[i + 5];
    if (validity.length !== 2) throw new X509Error("Validity must hold notBefore and notAfter");
    expectSequence(spkiEl, "SubjectPublicKeyInfo");
    let extensions: Extension[] = [];
    for (let j = i + 6; j < tbs.length; j++) {
      const f = tbs[j];
      if (isContext(f, 1) || isContext(f, 2)) {
        if (version < 1n) throw new X509Error("unique identifiers require version 2 or 3");
        continue;
      }
      if (isContext(f, 3) && f.constructed && j === tbs.length - 1) {
        if (version !== 2n) throw new X509Error("extensions require version 3");
        extensions = parseExtensions(f);
        continue;
      }
      throw new X509Error("unexpected field in TBSCertificate");
    }
    if (!bytesEqual(innerAlg.raw, outerAlg.raw)) throw new X509Error("inner and outer signature algorithms differ");
    const alg = signatureAlgorithm(outerAlg);
    const signature = bitString(sigEl);
    const subjectCommonName = commonName(subjectEl);
    expectSequence(issuerEl, "issuer Name");
    return {
      raw: der,
      tbs: tbsEl.raw,
      serialNumber,
      issuer: issuerEl.raw,
      subject: subjectEl.raw,
      ...(subjectCommonName !== undefined ? { subjectCommonName } : {}),
      notBefore: time(validity[0]),
      notAfter: time(validity[1]),
      spki: spkiEl.raw,
      signatureAlgorithm: alg,
      signature,
      extensions,
    };
  });
}

// ---------------------------------------------------------------- signature verification

type PublicKeyKind = { kind: "ec"; curve: "P-256" | "P-384" } | { kind: "rsa"; spki: Uint8Array };

/**
 * Classifies an SPKI by its algorithm. An RSA key labelled id-RSASSA-PSS is
 * relabelled rsaEncryption: the two carry the same RSAPublicKey, and WebCrypto
 * (Node and the browsers) accepts only the rsaEncryption label for import.
 */
function classifyKey(spki: Uint8Array): PublicKeyKind {
  const parts = expectSequence(decode(spki), "SubjectPublicKeyInfo");
  if (parts.length !== 2) throw new X509Error("SubjectPublicKeyInfo must hold an algorithm and a key");
  const alg = expectSequence(parts[0], "key AlgorithmIdentifier");
  if (alg.length === 0 || alg.length > 2) throw new X509Error("key AlgorithmIdentifier must hold an OID and optional parameters");
  const id = oid(alg[0]);
  switch (id) {
    case OID_EC_PUBLIC_KEY: {
      if (alg[1] === undefined) throw new X509Error("EC key must name its curve");
      const curve = oid(alg[1]);
      if (curve === OID_P256) return { kind: "ec", curve: "P-256" };
      if (curve === OID_P384) return { kind: "ec", curve: "P-384" };
      throw new X509Error(`unsupported EC curve ${curve}`);
    }
    case OID_RSA_ENCRYPTION:
      if (alg[1] !== undefined && !isUniversal(alg[1], TAG.NULL)) throw new X509Error("RSA key parameters must be NULL");
      return { kind: "rsa", spki };
    case OID_RSA_PSS: {
      const algId = concat(new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), new Uint8Array([0x05, 0x00]));
      const algSeq = concat(new Uint8Array([0x30]), encodeLength(algId.length), algId);
      const body = concat(algSeq, parts[1].raw);
      return { kind: "rsa", spki: concat(new Uint8Array([0x30]), encodeLength(body.length), body) };
    }
    default:
      throw new X509Error(`unsupported public key algorithm ${id}`);
  }
}

function asBuffer(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return b as Uint8Array<ArrayBuffer>;
}

/**
 * Verifies `signature` over `data` with the key in `spki`, for one of the
 * supported algorithms. Returns false for any mismatch between the algorithm
 * and the key, an unusable key, a malformed signature, or a bad signature.
 */
export async function verifySignatureWith(
  algorithm: SignatureAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  spki: Uint8Array,
): Promise<boolean> {
  let key: PublicKeyKind;
  try {
    key = classifyKey(spki);
  } catch (e) {
    if (e instanceof X509Error || e instanceof DerError) return false;
    throw e;
  }
  try {
    switch (algorithm) {
      case "ecdsa-p256-sha256":
      case "ecdsa-p384-sha384": {
        const curve = algorithm === "ecdsa-p256-sha256" ? "P-256" : "P-384";
        if (key.kind !== "ec" || key.curve !== curve) return false;
        const size = curve === "P-256" ? 32 : 48;
        const hash = curve === "P-256" ? "SHA-256" : "SHA-384";
        let raw: Uint8Array;
        try {
          raw = ecdsaSignatureToRaw(signature, size);
        } catch (e) {
          if (e instanceof DerError) return false;
          throw e;
        }
        const k = await crypto.subtle.importKey("spki", asBuffer(spki), { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
        return await crypto.subtle.verify({ name: "ECDSA", hash }, k, asBuffer(raw), asBuffer(data));
      }
      case "rsa-pss-sha384": {
        if (key.kind !== "rsa") return false;
        const k = await crypto.subtle.importKey("spki", asBuffer(key.spki), { name: "RSA-PSS", hash: "SHA-384" }, false, ["verify"]);
        return await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 48 }, k, asBuffer(signature), asBuffer(data));
      }
      case "rsa-pkcs1-sha256": {
        if (key.kind !== "rsa") return false;
        const k = await crypto.subtle.importKey("spki", asBuffer(key.spki), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, [
          "verify",
        ]);
        return await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, k, asBuffer(signature), asBuffer(data));
      }
    }
  } catch {
    // Key import or verification refused the material (wrong key size,
    // malformed key, oversized signature): the signature does not verify.
    return false;
  }
}

/** Verifies `cert`'s signature with the issuer's public key. */
export async function verifyCertificateSignature(cert: Certificate, issuerSpki: Uint8Array): Promise<boolean> {
  return verifySignatureWith(cert.signatureAlgorithm, cert.tbs, cert.signature, issuerSpki);
}

/** The extension with the given OID, if present. */
export function extension(cert: Certificate, oid: string): Extension | undefined {
  return cert.extensions.find((e) => e.oid === oid);
}

// ---------------------------------------------------------------- chain verification

export interface BasicConstraints {
  readonly ca: boolean;
  readonly pathLength?: bigint;
}

/** The basicConstraints extension, or undefined when absent. */
export function basicConstraints(cert: Certificate): BasicConstraints | undefined {
  const ext = extension(cert, OID_BASIC_CONSTRAINTS);
  if (ext === undefined) return undefined;
  return withContext("basicConstraints", () => {
    const parts = expectSequence(decode(ext.value), "BasicConstraints");
    if (parts.length > 2) throw new X509Error("BasicConstraints holds too many fields");
    let ca = false;
    let i = 0;
    if (parts.length > 0 && isUniversal(parts[0], TAG.BOOLEAN)) {
      ca = boolean(parts[0]);
      if (!ca) throw new X509Error("BasicConstraints encodes the default cA value");
      i = 1;
    }
    if (i < parts.length) {
      if (i + 1 !== parts.length) throw new X509Error("BasicConstraints holds an unexpected field");
      return { ca, pathLength: integer(parts[i]) };
    }
    return { ca };
  });
}

/** The keyUsage bits as a boolean array indexed by bit position, or undefined when absent. */
export function keyUsage(cert: Certificate): boolean[] | undefined {
  const ext = extension(cert, OID_KEY_USAGE);
  if (ext === undefined) return undefined;
  return withContext("keyUsage", () => {
    const el = decode(ext.value);
    if (!isUniversal(el, TAG.BIT_STRING)) throw new X509Error("KeyUsage must be a BIT STRING");
    const unused = el.value[0];
    const bits: boolean[] = [];
    for (let i = 1; i < el.value.length; i++) {
      const last = i === el.value.length - 1;
      for (let j = 7; j >= (last ? unused : 0); j--) bits.push(((el.value[i] >> j) & 1) === 1);
    }
    return bits;
  });
}

/** Whether `cert` may issue certificates: basicConstraints cA, and keyCertSign when keyUsage is present. */
export function canIssueCertificates(cert: Certificate): boolean {
  if (!basicConstraints(cert)?.ca) return false;
  const usage = keyUsage(cert);
  return usage === undefined || usage[KEY_USAGE_KEY_CERT_SIGN] === true;
}

/** Whether `cert` may sign revocation lists: basicConstraints cA, and cRLSign when keyUsage is present. */
export function canSignRevocationLists(cert: Certificate): boolean {
  if (!basicConstraints(cert)?.ca) return false;
  const usage = keyUsage(cert);
  return usage === undefined || usage[KEY_USAGE_CRL_SIGN] === true;
}

export function validAt(cert: Certificate, at: Date): boolean {
  const t = at.getTime();
  return cert.notBefore.getTime() <= t && t <= cert.notAfter.getTime();
}

function describe(cert: Certificate, index: number): string {
  return cert.subjectCommonName !== undefined ? `certificate ${index} (${cert.subjectCommonName})` : `certificate ${index}`;
}

/**
 * Verifies a chain leaf → … → root: each signature with the next
 * certificate's key, issuer/subject names matching byte for byte, every
 * certificate valid at `at`, and every issuing certificate (intermediates and
 * the root) asserting basicConstraints cA. The root must be one of `roots`.
 */
export async function verifyChain(chain: readonly Certificate[], roots: readonly Certificate[], at: Date): Promise<void> {
  if (chain.length === 0) throw new X509Error("certificate chain is empty");
  if (Number.isNaN(at.getTime())) throw new X509Error("verification time is invalid");
  const last = chain[chain.length - 1];
  if (!roots.some((r) => bytesEqual(r.raw, last.raw))) throw new X509Error("chain does not end in a trusted root");
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    if (!validAt(cert, at)) throw new X509Error(`${describe(cert, i)} is not valid at ${at.toISOString()}`);
    if (i === 0) continue;
    // Every certificate above the leaf issues the one below it.
    if (!canIssueCertificates(cert)) throw new X509Error(`${describe(cert, i)} is not a certificate authority`);
    const pathLength = basicConstraints(cert)?.pathLength;
    // The issuers between this one and the leaf must fit its path length.
    if (pathLength !== undefined && BigInt(i - 1) > pathLength) {
      throw new X509Error(`${describe(cert, i)} path length constraint exceeded`);
    }
  }
  for (let i = 0; i + 1 < chain.length; i++) {
    const cert = chain[i];
    const issuer = chain[i + 1];
    if (!bytesEqual(cert.issuer, issuer.subject)) {
      throw new X509Error(`${describe(cert, i)} issuer does not match ${describe(issuer, i + 1)} subject`);
    }
    if (!(await verifyCertificateSignature(cert, issuer.spki))) {
      throw new X509Error(`${describe(cert, i)} signature does not verify under ${describe(issuer, i + 1)}`);
    }
  }
}

/** SHA-256 of the DER SubjectPublicKeyInfo, lowercase hex: the TLS pinning fingerprint form. */
export async function spkiFingerprint(spki: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", asBuffer(spki))));
}
