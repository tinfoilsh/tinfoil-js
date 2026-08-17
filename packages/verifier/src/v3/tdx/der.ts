// Minimal strict-DER reader for the X.509 material TDX verification touches:
// certificates, CRLs, PEM blocks, and name/extension access. WebCrypto (via
// ../crypto.js) verifies the signatures but exposes neither CRLs nor
// arbitrary extensions, so structure parsing is manual. All errors are plain
// Errors; callers assign the rejection layer.

import { bytesToLatin1, decodeBase64, encodeHex, utf8DecodeLenient } from "../bytes.js";
import { derEcdsaSignatureToRaw, importEcdsaSpki, verifyP256Raw } from "../crypto.js";

export { bytesToLatin1 };

// ASN.1 tag numbers used below (universal class).
const tagInteger = 0x02;
const tagBitString = 0x03;
const tagOctetString = 0x04;
const tagOID = 0x06;
const tagUTF8String = 0x0c;
const tagSequence = 0x10;
const tagSet = 0x11;
const tagPrintableString = 0x13;
const tagIA5String = 0x16;
const tagUTCTime = 0x17;
const tagGeneralizedTime = 0x18;

export interface TLV {
  cls: number; // 0 universal, 2 context
  constructed: boolean;
  tag: number;
  start: number; // offset of the tag byte
  contentStart: number;
  end: number; // one past the last content byte
}

export function readTLV(b: Uint8Array, off: number): TLV {
  if (off + 2 > b.length) throw new Error("truncated DER element");
  const first = b[off];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  const tag = first & 0x1f;
  if (tag === 0x1f) throw new Error("multi-byte DER tags are not supported");
  let len = b[off + 1];
  let contentStart = off + 2;
  if (len === 0x80) throw new Error("indefinite DER length");
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4 || off + 2 + n > b.length) throw new Error("invalid DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i];
    contentStart = off + 2 + n;
  }
  const end = contentStart + len;
  if (end > b.length) throw new Error("DER element overruns input");
  return { cls, constructed, tag, start: off, contentStart, end };
}

export function content(b: Uint8Array, t: TLV): Uint8Array {
  return b.subarray(t.contentStart, t.end);
}

function raw(b: Uint8Array, t: TLV): Uint8Array {
  return b.subarray(t.start, t.end);
}

function expectTag(b: Uint8Array, off: number, tag: number, what: string): TLV {
  const t = readTLV(b, off);
  if (t.cls !== 0 || t.tag !== tag) {
    throw new Error(`expected ${what}, found tag ${t.cls}/${t.tag}`);
  }
  return t;
}

// children splits a constructed element's content into its child TLVs.
export function children(b: Uint8Array, t: TLV): TLV[] {
  const out: TLV[] = [];
  let off = t.contentStart;
  while (off < t.end) {
    const c = readTLV(b, off);
    out.push(c);
    off = c.end;
  }
  return out;
}

export function decodeOID(b: Uint8Array): string {
  if (b.length === 0) throw new Error("empty OID");
  const parts: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

// decodeUint parses a DER INTEGER content as an unsigned number (throws on
// negative or oversized values), mirroring Go's asn1 int64 decoding limits
// the SGX extension parser relies on.
export function decodeUint(b: Uint8Array, what: string): number {
  if (b.length === 0) throw new Error(`${what}: empty integer`);
  if ((b[0] & 0x80) !== 0) throw new Error(`${what}: negative integer`);
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  if (b.length - start > 6) throw new Error(`${what}: integer too large`);
  let v = 0;
  for (let i = start; i < b.length; i++) v = v * 256 + b[i];
  return v;
}

function serialHexFromInteger(b: Uint8Array): string {
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  return encodeHex(b.subarray(start));
}

function parseTime(b: Uint8Array, t: TLV): Date {
  const s = bytesToLatin1(content(b, t));
  let iso: string;
  if (t.tag === tagUTCTime) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error(`invalid UTCTime ${JSON.stringify(s)}`);
    const yy = parseInt(m[1], 10);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    iso = `${year}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  } else if (t.tag === tagGeneralizedTime) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error(`invalid GeneralizedTime ${JSON.stringify(s)}`);
    iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  } else {
    throw new Error("expected UTCTime or GeneralizedTime");
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) throw new Error(`invalid time ${JSON.stringify(s)}`);
  return d;
}

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

export interface Extension {
  oid: string;
  critical: boolean;
  value: Uint8Array; // extnValue OCTET STRING contents
}

function parseExtensions(b: Uint8Array, extSeq: TLV): Extension[] {
  const out: Extension[] = [];
  for (const ext of children(b, extSeq)) {
    const parts = children(b, ext);
    if (parts.length < 2 || parts.length > 3 || parts[0].tag !== tagOID) {
      throw new Error("malformed X.509 extension");
    }
    const oid = decodeOID(content(b, parts[0]));
    let critical = false;
    let valueIdx = 1;
    if (parts.length === 3) {
      critical = content(b, parts[1])[0] !== 0;
      valueIdx = 2;
    }
    if (parts[valueIdx].tag !== tagOctetString) throw new Error("extension value is not an OCTET STRING");
    out.push({ oid, critical, value: content(b, parts[valueIdx]) });
  }
  return out;
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

function bitStringBytes(b: Uint8Array, t: TLV, what: string): Uint8Array {
  const c = content(b, t);
  if (c.length === 0 || c[0] !== 0) throw new Error(`${what}: unsupported BIT STRING padding`);
  return c.subarray(1);
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
  const spkiDER = raw(der, spkiT);
  return {
    raw: der,
    tbs: raw(der, tbsT),
    version,
    serialHex: serialHexFromInteger(content(der, serialT)),
    signatureAlgorithmOID: algorithmOID(der, sigAlgT),
    issuerDER: raw(der, issuerT),
    issuerCN: nameCN(der, issuerT),
    subjectDER: raw(der, subjectT),
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
    tbs: raw(der, tbsT),
    signatureAlgorithmOID: algorithmOID(der, sigAlgT),
    issuerDER: raw(der, issuerT),
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

// PEM handling (Go encoding/pem.Decode subset: first block + rest).

export interface PEMBlock {
  type: string;
  der: Uint8Array;
  rest: string;
}

const pemRE = /-----BEGIN ([^-]+)-----\r?\n([A-Za-z0-9+/=\r\n]*)-----END \1-----(?:\r?\n)?/;

export function pemDecode(text: string): PEMBlock | undefined {
  const m = pemRE.exec(text);
  if (!m) return undefined;
  const b64 = m[2].replace(/[\r\n]/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64)) return undefined;
  return {
    type: m[1],
    der: decodeBase64(b64),
    rest: text.slice((m.index ?? 0) + m[0].length),
  };
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

export function derBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
