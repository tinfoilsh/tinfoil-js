// SEV-specific X.509 parsing over the shared strict-DER reader (../der.js):
// AMD certificates (RSA-PSS roots, ECDSA VCEK), CRLs, names, and extensions.
// WebCrypto (via ../crypto.js) verifies the signatures but exposes neither
// CRLs nor arbitrary extensions, so structure parsing is manual. All errors
// are plain Errors; callers assign the rejection layer.

import { bytesToLatin1, utf8DecodeLenient } from "../bytes.js";
import { verifyRsaPssSha384 } from "../crypto.js";
import {
  bitStringBytes,
  children,
  content,
  decodeOID,
  decodeUint,
  expectTag,
  parseExtensions,
  parseTime,
  rawOf,
  readTLV,
  serialHexFromInteger,
  tagBoolean,
  tagIA5String,
  tagInteger,
  tagOID,
  tagPrintableString,
  tagSequence,
  tagSet,
  tagUTCTime,
  tagGeneralizedTime,
  tagUTF8String,
  type Extension,
  type TLV,
} from "../der.js";

// parseName collects an X.501 Name's attribute values keyed by dotted
// attribute-type OID, preserving multiplicity (Go pkix.Name lists).
export function parseName(b: Uint8Array, name: TLV): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const rdn of children(b, name)) {
    if (rdn.cls !== 0 || rdn.tag !== tagSet) continue;
    for (const atv of children(b, rdn)) {
      const parts = children(b, atv);
      if (parts.length !== 2 || parts[0].tag !== tagOID) continue;
      const oid = decodeOID(content(b, parts[0]));
      const vt = parts[1];
      if (vt.tag !== tagUTF8String && vt.tag !== tagPrintableString && vt.tag !== tagIA5String) continue;
      const value = utf8DecodeLenient(content(b, vt));
      const list = out.get(oid);
      if (list === undefined) out.set(oid, [value]);
      else list.push(value);
    }
  }
  return out;
}

// Attribute-type OIDs (RFC 5280 / pkix.Name fields).
export const oidCommonName = "2.5.4.3";
export const oidCountry = "2.5.4.6";
export const oidLocality = "2.5.4.7";
export const oidProvince = "2.5.4.8";
export const oidOrganization = "2.5.4.10";
export const oidOrganizationalUnit = "2.5.4.11";

// SignatureAlgorithm identifies the algorithm plus the RSASSA-PSS parameters
// Go's x509 requires to classify it (hash == MGF1 hash, salt == hash size).
export interface SignatureAlgorithm {
  oid: string;
  pssHashOID: string; // "" when not RSASSA-PSS
  pssMGF1HashOID: string;
  pssSaltLength: number;
}

export const oidRSASSAPSS = "1.2.840.113549.1.1.10";
export const oidSHA384 = "2.16.840.1.101.3.4.2.2";
export const oidSHA1 = "1.3.14.3.2.26";
export const oidECPublicKey = "1.2.840.10045.2.1";
export const oidP384 = "1.3.132.0.34";
export const oidAuthorityKeyID = "2.5.29.35";
const oidKeyUsage = "2.5.29.15";
const oidBasicConstraints = "2.5.29.19";
const oidCRLDistributionPoints = "2.5.29.31";

function parseAlgorithmIdentifier(b: Uint8Array, alg: TLV): SignatureAlgorithm {
  const parts = children(b, alg);
  if (parts.length === 0 || parts[0].tag !== tagOID) throw new Error("malformed AlgorithmIdentifier");
  const out: SignatureAlgorithm = {
    oid: decodeOID(content(b, parts[0])),
    pssHashOID: "",
    pssMGF1HashOID: "",
    pssSaltLength: 0,
  };
  if (out.oid !== oidRSASSAPSS) return out;
  // RSASSA-PSS-params defaults (RFC 4055): SHA-1, MGF1-SHA-1, salt 20.
  out.pssHashOID = oidSHA1;
  out.pssMGF1HashOID = oidSHA1;
  out.pssSaltLength = 20;
  if (parts.length < 2 || parts[1].tag !== tagSequence) return out;
  for (const p of children(b, parts[1])) {
    if (p.cls !== 2) continue;
    switch (p.tag) {
      case 0: {
        const h = readTLV(b, p.contentStart);
        out.pssHashOID = decodeOID(content(b, readTLV(b, h.contentStart)));
        break;
      }
      case 1: {
        const mgf = readTLV(b, p.contentStart);
        const mgfParts = children(b, mgf);
        if (mgfParts.length === 2 && mgfParts[1].tag === tagSequence) {
          out.pssMGF1HashOID = decodeOID(content(b, readTLV(b, mgfParts[1].contentStart)));
        }
        break;
      }
      case 2: {
        const salt = expectTag(b, p.contentStart, tagInteger, "PSS salt length");
        out.pssSaltLength = decodeUint(content(b, salt), "PSS salt length");
        break;
      }
    }
  }
  return out;
}

// isPSSSHA384 reports whether alg is what Go x509 classifies as
// SHA384WithRSAPSS.
export function isPSSSHA384(alg: SignatureAlgorithm): boolean {
  return (
    alg.oid === oidRSASSAPSS &&
    alg.pssHashOID === oidSHA384 &&
    alg.pssMGF1HashOID === oidSHA384 &&
    alg.pssSaltLength === 48
  );
}

// Key usage bit values (Go x509.KeyUsage).
export const keyUsageCertSign = 1 << 5;
export const keyUsageCRLSign = 1 << 6;

function parseKeyUsage(value: Uint8Array): number {
  const t = readTLV(value, 0);
  if (t.cls !== 0 || t.tag !== 0x03) throw new Error("keyUsage is not a BIT STRING");
  const c = content(value, t);
  if (c.length < 2) return 0;
  let usage = 0;
  for (let i = 0; i < 9; i++) {
    const byte = c[1 + (i >> 3)];
    if (byte === undefined) break;
    if ((byte >> (7 - (i & 7))) & 1) usage |= 1 << i;
  }
  return usage;
}

export interface Certificate {
  raw: Uint8Array;
  tbs: Uint8Array; // full TBSCertificate element
  version: number; // 1-based (v3 == 3), like Go
  serialHex: string;
  signatureAlgorithm: SignatureAlgorithm;
  issuerDER: Uint8Array;
  issuer: Map<string, string[]>;
  subjectDER: Uint8Array;
  subject: Map<string, string[]>;
  notBefore: Date;
  notAfter: Date;
  spkiAlgorithmOID: string;
  spkiCurveOID: string;
  extensions: Extension[];
  basicConstraintsValid: boolean;
  isCA: boolean;
  keyUsage: number; // 0 when the extension is absent (Go zero value)
  crlDistributionPoints: string[];
  signature: Uint8Array; // BIT STRING contents
  spkiDER: Uint8Array; // full SubjectPublicKeyInfo element
}

// crlDistributionPointURIs returns the URI GeneralNames of a CRL
// Distribution Points extension value.
function crlDistributionPointURIs(value: Uint8Array): string[] {
  const out: string[] = [];
  const seq = readTLV(value, 0);
  for (const dp of children(value, seq)) {
    for (const dpName of children(value, dp)) {
      if (dpName.cls !== 2 || dpName.tag !== 0) continue; // [0] distributionPoint
      for (const fullName of children(value, dpName)) {
        if (fullName.cls !== 2 || fullName.tag !== 0) continue; // [0] fullName
        for (const gn of children(value, fullName)) {
          if (gn.cls === 2 && gn.tag === 6) {
            // [6] uniformResourceIdentifier
            out.push(bytesToLatin1(value.subarray(gn.contentStart, gn.end)));
          }
        }
      }
    }
  }
  return out;
}

export function parseCertificate(der: Uint8Array): Certificate {
  const outer = expectTag(der, 0, tagSequence, "Certificate SEQUENCE");
  if (outer.end !== der.length) throw new Error("trailing bytes after certificate");
  const [tbsT, sigAlgT, sigT] = children(der, outer);
  if (tbsT === undefined || sigAlgT === undefined || sigT === undefined) {
    throw new Error("malformed certificate");
  }
  const tbsParts = children(der, tbsT);
  let i = 0;
  let version = 1;
  if (tbsParts[i] !== undefined && tbsParts[i].cls === 2 && tbsParts[i].tag === 0) {
    const vInt = expectTag(der, tbsParts[i].contentStart, tagInteger, "version INTEGER");
    version = decodeUint(content(der, vInt), "version") + 1;
    i++;
  }
  const serialT = expectTag(der, tbsParts[i].start, tagInteger, "serialNumber");
  i++;
  i++; // inner signature AlgorithmIdentifier (outer one is authoritative)
  const issuerT = tbsParts[i++];
  const validityT = tbsParts[i++];
  const subjectT = tbsParts[i++];
  const spkiT = tbsParts[i++];
  if (spkiT === undefined) throw new Error("malformed TBSCertificate");
  let extensions: Extension[] = [];
  for (; i < tbsParts.length; i++) {
    if (tbsParts[i].cls === 2 && tbsParts[i].tag === 3) {
      extensions = parseExtensions(der, readTLV(der, tbsParts[i].contentStart));
    }
  }
  const [notBeforeT, notAfterT] = children(der, validityT);
  const spkiParts = children(der, spkiT);
  if (spkiParts.length !== 2) throw new Error("malformed SubjectPublicKeyInfo");
  const spkiAlgParts = children(der, spkiParts[0]);
  if (spkiAlgParts.length === 0 || spkiAlgParts[0].tag !== tagOID) {
    throw new Error("malformed SubjectPublicKeyInfo algorithm");
  }
  let spkiCurveOID = "";
  if (spkiAlgParts.length === 2 && spkiAlgParts[1].tag === tagOID) {
    spkiCurveOID = decodeOID(content(der, spkiAlgParts[1]));
  }

  let basicConstraintsValid = false;
  let isCA = false;
  let keyUsage = 0;
  let crlDPs: string[] = [];
  for (const ext of extensions) {
    switch (ext.oid) {
      case oidBasicConstraints: {
        basicConstraintsValid = true;
        const seq = expectTag(ext.value, 0, tagSequence, "BasicConstraints SEQUENCE");
        const parts = children(ext.value, seq);
        if (parts.length > 0 && parts[0].cls === 0 && parts[0].tag === tagBoolean) {
          isCA = content(ext.value, parts[0])[0] !== 0;
        }
        break;
      }
      case oidKeyUsage:
        keyUsage = parseKeyUsage(ext.value);
        break;
      case oidCRLDistributionPoints:
        crlDPs = crlDistributionPointURIs(ext.value);
        break;
    }
  }

  return {
    raw: der,
    tbs: rawOf(der, tbsT),
    version,
    serialHex: serialHexFromInteger(content(der, serialT)),
    signatureAlgorithm: parseAlgorithmIdentifier(der, sigAlgT),
    issuerDER: rawOf(der, issuerT),
    issuer: parseName(der, issuerT),
    subjectDER: rawOf(der, subjectT),
    subject: parseName(der, subjectT),
    notBefore: parseTime(der, notBeforeT),
    notAfter: parseTime(der, notAfterT),
    spkiAlgorithmOID: decodeOID(content(der, spkiAlgParts[0])),
    spkiCurveOID,
    extensions,
    basicConstraintsValid,
    isCA,
    keyUsage,
    crlDistributionPoints: crlDPs,
    signature: bitStringBytes(der, sigT, "certificate signature"),
    spkiDER: rawOf(der, spkiT),
  };
}

export interface CRL {
  raw: Uint8Array;
  tbs: Uint8Array;
  signatureAlgorithm: SignatureAlgorithm;
  issuerDER: Uint8Array;
  thisUpdate: Date;
  nextUpdate: Date; // zero time when absent (Go's zero time behaves the same)
  revokedSerialsHex: string[];
  signature: Uint8Array;
}

export function parseCRL(der: Uint8Array): CRL {
  const outer = expectTag(der, 0, tagSequence, "CertificateList SEQUENCE");
  if (outer.end !== der.length) throw new Error("trailing bytes after CRL");
  const [tbsT, sigAlgT, sigT] = children(der, outer);
  if (tbsT === undefined || sigAlgT === undefined || sigT === undefined || tbsT.tag !== tagSequence) {
    throw new Error("malformed CRL");
  }
  const tbsParts = children(der, tbsT);
  let i = 0;
  if (tbsParts[i] !== undefined && tbsParts[i].cls === 0 && tbsParts[i].tag === tagInteger) i++; // version
  const algT = tbsParts[i++];
  if (algT === undefined || algT.tag !== tagSequence) throw new Error("malformed CRL signature algorithm");
  const issuerT = tbsParts[i++];
  if (issuerT === undefined || issuerT.tag !== tagSequence) throw new Error("malformed CRL issuer");
  const thisUpdateT = tbsParts[i++];
  if (thisUpdateT === undefined || (thisUpdateT.tag !== tagUTCTime && thisUpdateT.tag !== tagGeneralizedTime)) {
    throw new Error("malformed CRL thisUpdate");
  }
  let nextUpdate = new Date(0);
  if (tbsParts[i] !== undefined && (tbsParts[i].tag === tagUTCTime || tbsParts[i].tag === tagGeneralizedTime)) {
    nextUpdate = parseTime(der, tbsParts[i]);
    i++;
  }
  const revokedSerialsHex: string[] = [];
  if (tbsParts[i] !== undefined && tbsParts[i].cls === 0 && tbsParts[i].tag === tagSequence) {
    for (const rc of children(der, tbsParts[i])) {
      const serialT = expectTag(der, rc.contentStart, tagInteger, "revoked serial");
      revokedSerialsHex.push(serialHexFromInteger(content(der, serialT)));
    }
    i++;
  }
  return {
    raw: der,
    tbs: rawOf(der, tbsT),
    signatureAlgorithm: parseAlgorithmIdentifier(der, sigAlgT),
    issuerDER: rawOf(der, issuerT),
    thisUpdate: parseTime(der, thisUpdateT),
    nextUpdate,
    revokedSerialsHex,
    signature: bitStringBytes(der, sigT, "CRL signature"),
  };
}

// Signature verification.

// verifyPSSSHA384 verifies an RSASSA-PSS SHA-384 signature with the salt
// length Go's x509 requires (equal to the hash size).
export function verifyPSSSHA384(message: Uint8Array, signature: Uint8Array, signerSpki: Uint8Array): Promise<boolean> {
  return verifyRsaPssSha384(signerSpki, signature, message, 48);
}
