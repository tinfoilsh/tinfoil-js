// TDX-specific X.509 parsing over the shared strict-DER reader (../der.js):
// certificates, CRLs, and name/extension access. WebCrypto (via ../crypto.js)
// verifies the signatures but exposes neither CRLs nor arbitrary extensions,
// so structure parsing is manual. All errors are plain Errors; callers assign
// the rejection layer.

import { bytesToLatin1, utf8DecodeLenient } from "../bytes.js";
import { derEcdsaSignatureToRaw, importEcdsaSpki, verifyP256Raw } from "../crypto.js";
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

// nameCN extracts the CommonName (OID 2.5.4.3) string from an X.501 Name.
function nameCN(b: Uint8Array, name: TLV): string {
  for (const rdn of children(b, name)) {
    if (rdn.cls !== 0 || rdn.tag !== tagSet) continue;
    for (const atv of children(b, rdn)) {
      const parts = children(b, atv);
      if (parts.length !== 2 || parts[0].tag !== tagOID) continue;
      if (decodeOID(content(b, parts[0])) !== "2.5.4.3") continue;
      const vt = parts[1];
      if (vt.tag === tagUTF8String || vt.tag === tagPrintableString || vt.tag === tagIA5String) {
        return utf8DecodeLenient(content(b, vt));
      }
    }
  }
  return "";
}

export interface Certificate {
  raw: Uint8Array;
  tbs: Uint8Array; // full TBSCertificate element
  version: number; // 1-based (v3 == 3), like Go
  serialHex: string;
  signatureAlgorithmOID: string;
  issuerDER: Uint8Array;
  issuerCN: string;
  subjectDER: Uint8Array;
  subjectCN: string;
  notBefore: Date;
  notAfter: Date;
  spkiDER: Uint8Array;
  spkiAlgorithmOID: string;
  spkiCurveOID: string;
  extensions: Extension[];
  signature: Uint8Array; // DER-encoded ECDSA signature (BIT STRING contents)
}

function algorithmOID(b: Uint8Array, alg: TLV): string {
  const parts = children(b, alg);
  if (parts.length === 0 || parts[0].tag !== tagOID) throw new Error("malformed AlgorithmIdentifier");
  return decodeOID(content(b, parts[0]));
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
  const spkiAlgorithmOID = algorithmOID(der, spkiParts[0]);
  let spkiCurveOID = "";
  if (spkiAlgParts.length === 2 && spkiAlgParts[1].tag === tagOID) {
    spkiCurveOID = decodeOID(content(der, spkiAlgParts[1]));
  }
  const spkiDER = rawOf(der, spkiT);
  return {
    raw: der,
    tbs: rawOf(der, tbsT),
    version,
    serialHex: serialHexFromInteger(content(der, serialT)),
    signatureAlgorithmOID: algorithmOID(der, sigAlgT),
    issuerDER: rawOf(der, issuerT),
    issuerCN: nameCN(der, issuerT),
    subjectDER: rawOf(der, subjectT),
    subjectCN: nameCN(der, subjectT),
    notBefore: parseTime(der, notBeforeT),
    notAfter: parseTime(der, notAfterT),
    spkiDER,
    spkiAlgorithmOID,
    spkiCurveOID,
    extensions,
    signature: bitStringBytes(der, sigT, "certificate signature"),
  };
}

export interface CRL {
  raw: Uint8Array;
  tbs: Uint8Array;
  signatureAlgorithmOID: string;
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
  algorithmOID(der, algT);
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
    signatureAlgorithmOID: algorithmOID(der, sigAlgT),
    issuerDER: rawOf(der, issuerT),
    thisUpdate: parseTime(der, thisUpdateT),
    nextUpdate,
    revokedSerialsHex,
    signature: bitStringBytes(der, sigT, "CRL signature"),
  };
}

// basicConstraints mirrors Go's BasicConstraintsValid / IsCA: present is
// true when the extension (OID 2.5.29.19) exists and parses.
export function basicConstraints(cert: Certificate): { present: boolean; ca: boolean } {
  const ext = cert.extensions.find((e) => e.oid === "2.5.29.19");
  if (ext === undefined) return { present: false, ca: false };
  const seq = readTLV(ext.value, 0);
  let ca = false;
  const parts = children(ext.value, seq);
  if (parts.length > 0 && parts[0].cls === 0 && parts[0].tag === 0x01) {
    ca = content(ext.value, parts[0])[0] !== 0;
  }
  return { present: true, ca };
}

// keyUsage returns the CertSign/CRLSign bits of the KeyUsage extension
// (OID 2.5.29.15; asn1 bits 5 and 6 counted from the MSB).
export function keyUsage(cert: Certificate): { present: boolean; certSign: boolean; crlSign: boolean } {
  const ext = cert.extensions.find((e) => e.oid === "2.5.29.15");
  if (ext === undefined) return { present: false, certSign: false, crlSign: false };
  const bits = readTLV(ext.value, 0);
  const c = content(ext.value, bits);
  const first = c.length > 1 ? c[1] : 0; // c[0] is the unused-bits count
  return { present: true, certSign: (first & 0x04) !== 0, crlSign: (first & 0x02) !== 0 };
}

// crlDistributionPointURIs returns the URI GeneralNames of the CRL
// Distribution Points extension (OID 2.5.29.31), or an empty list.
export function crlDistributionPointURIs(cert: Certificate): string[] {
  const ext = cert.extensions.find((e) => e.oid === "2.5.29.31");
  if (ext === undefined) return [];
  const out: string[] = [];
  const seq = readTLV(ext.value, 0);
  for (const dp of children(ext.value, seq)) {
    for (const dpName of children(ext.value, dp)) {
      if (dpName.cls !== 2 || dpName.tag !== 0) continue; // [0] distributionPoint
      for (const fullName of children(ext.value, dpName)) {
        if (fullName.cls !== 2 || fullName.tag !== 0) continue; // [0] fullName
        for (const gn of children(ext.value, fullName)) {
          if (gn.cls === 2 && gn.tag === 6) {
            // [6] uniformResourceIdentifier
            out.push(bytesToLatin1(ext.value.subarray(gn.contentStart, gn.end)));
          }
        }
      }
    }
  }
  return out;
}

// Signature verification helpers (ECDSA-P256-SHA256 only, matching Intel).

export function verifyDERSignature(message: Uint8Array, signature: Uint8Array, signer: Certificate): Promise<boolean> {
  const raw = derEcdsaSignatureToRaw(signature, 32);
  if (raw === undefined) return Promise.resolve(false);
  return verifyP256Raw(signer.spkiDER, raw, message);
}

// verifyRawSignature verifies a raw r||s (64-byte) ECDSA-P256 signature.
export function verifyRawSignature(message: Uint8Array, signature: Uint8Array, spkiDER: Uint8Array): Promise<boolean> {
  if (signature.length !== 64) return Promise.resolve(false);
  return verifyP256Raw(spkiDER, signature, message);
}

// SPKI prefix for id-ecPublicKey on prime256v1 with an uncompressed point.
const p256SpkiPrefixHex = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";

// ecdsaP256PublicKey builds an SPKI from raw X||Y bytes (Go
// bytesToEcdsaPubKey; key import fails for malformed points).
export async function ecdsaP256PublicKey(xy: Uint8Array): Promise<Uint8Array> {
  if (xy.length !== 64) throw new Error("public key is of unexpected size");
  const prefix = p256SpkiPrefixHex;
  const spki = new Uint8Array(prefix.length / 2 + 64);
  for (let i = 0; i < prefix.length / 2; i++) spki[i] = parseInt(prefix.slice(2 * i, 2 * i + 2), 16);
  spki.set(xy, prefix.length / 2);
  try {
    await importEcdsaSpki(spki, "P-256"); // point validation
  } catch (err) {
    throw new Error(`attestation key is invalid: ${err instanceof Error ? err.message : String(err)}`);
  }
  return spki;
}
