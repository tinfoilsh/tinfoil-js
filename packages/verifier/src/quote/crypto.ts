import { ASN1Obj } from '@freedomofpress/crypto-browser';
import { X509Certificate } from '@freedomofpress/sigstore-browser';

export function requireThat(ok: unknown, message: string): asserts ok {
  if (!ok) throw new Error(message);
}
export const hex = (b: Uint8Array): string => Array.from(b, n => n.toString(16).padStart(2, '0')).join('');
export const equal = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((n, i) => n === b[i]);
export const zero = (a: Uint8Array): boolean => a.every(n => n === 0);
export function unhex(s: string, size?: number): Uint8Array {
  requireThat(typeof s === 'string' && /^(?:[a-fA-F0-9]{2})*$/.test(s) && (size === undefined || s.length === size * 2), 'invalid hexadecimal field');
  return Uint8Array.from(s.match(/../g) ?? [], c => parseInt(c, 16));
}
export function concat(...values: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(values.reduce((n, v) => n + v.length, 0));
  let offset = 0;
  for (const value of values) { out.set(value, offset); offset += value.length; }
  return out;
}
export const buffer = (b: Uint8Array): ArrayBuffer => Uint8Array.from(b).buffer as ArrayBuffer;
export async function digest(algorithm: string, b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(algorithm, buffer(b)));
}

// The existing ASN.1 library supplies the parser. A DER round trip closes its
// permissive trailing-data/length behavior; primitive checks reject BER values.
export function der(bytes: Uint8Array): ASN1Obj {
  const obj = ASN1Obj.parseBuffer(bytes);
  requireThat(equal(obj.toDER(), bytes), 'noncanonical or trailing DER data');
  function check(node: ASN1Obj, depth: number): void {
    requireThat(depth < 32, 'DER nesting limit exceeded');
    if (node.tag.isInteger()) {
      const v = node.value;
      requireThat(v.length > 0 && !(v.length > 1 && ((v[0] === 0 && v[1] < 128) || (v[0] === 255 && v[1] >= 128))), 'noncanonical DER integer');
    }
    if (node.tag.isBoolean()) requireThat(node.value.length === 1 && (node.value[0] === 0 || node.value[0] === 255), 'noncanonical DER boolean');
    if (node.tag.isBitString()) {
      const v = node.value;
      requireThat(v.length > 0 && v[0] <= 7 && (v.length > 1 || v[0] === 0) && (v[v.length - 1] & ((1 << v[0]) - 1)) === 0, 'invalid DER bit string');
    }
    // OCTET STRING contents are opaque; extensions are parsed separately.
    if (node.tag.constructed) for (const child of node.subs) check(child, depth + 1);
  }
  check(obj, 0);
  return obj;
}
export function integer(obj: ASN1Obj, max = 0xffffffffffffffffn): bigint {
  const n = obj.toInteger();
  requireThat(n >= 0 && n <= max, 'DER integer out of range');
  return n;
}
export function pemCertificates(pem: string): X509Certificate[] {
  const out: X509Certificate[] = [];
  let rest = pem.trim();
  while (rest) {
    const match = /^-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----/.exec(rest);
    requireThat(match, 'invalid certificate PEM chain');
    const encoded = match[1].replace(/\s/g, '');
    const bytes = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
    requireThat(btoa(String.fromCharCode(...bytes)) === encoded, 'noncanonical certificate base64');
    out.push(certificate(bytes));
    rest = rest.slice(match[0].length).trim();
  }
  requireThat(out.length > 0, 'empty certificate chain');
  return out;
}
export function certificate(bytes: Uint8Array): X509Certificate {
  const root = der(bytes);
  requireThat(root.tag.toDER() === 0x30 && root.subs.length === 3, 'invalid certificate');
  const cert = new X509Certificate(root);
  requireThat(cert.version === 'v3', 'X.509 v3 certificate required');
  const seen = new Set<string>();
  for (const ext of cert.extensions) {
    requireThat(ext.subs.length === 2 || ext.subs.length === 3, 'invalid certificate extension');
    const oid = ext.subs[0].toOID();
    requireThat(!seen.has(oid), 'duplicate certificate extension'); seen.add(oid);
    requireThat(ext.subs[ext.subs.length - 1].tag.isOctetString(), 'invalid certificate extension value');
    if (ext.subs.length === 3 && ext.subs[1].toBoolean()) {
      requireThat(['2.5.29.15', '2.5.29.19'].includes(oid), `unsupported critical extension ${oid}`);
    }
  }
  requireThat(equal(root.subs[1].toDER(), cert.tbsCertificate.subs[2].toDER()), 'certificate signature algorithms differ');
  return cert;
}
const hashes: Record<string, string> = { '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };
export async function verifySigned(issuer: X509Certificate, algorithm: ASN1Obj, signature: Uint8Array, data: Uint8Array): Promise<void> {
  const oid = algorithm.subs[0].toOID();
  let importAlgorithm: RsaHashedImportParams | EcKeyImportParams;
  let verifyAlgorithm: RsaPssParams | EcdsaParams | Algorithm;
  let sig = signature;
  if (oid === '1.2.840.113549.1.1.10') {
    const fields = algorithm.subs[1]?.subs;
    requireThat(fields && fields.length >= 3 && fields.length <= 4 && fields.every((f, i) => f.tag.isContextSpecific(i) && f.subs.length === 1), 'unsupported RSA-PSS parameters');
    const hash = hashes[fields[0].subs[0].subs[0].toOID()];
    const mgf = fields[1].subs[0];
    requireThat(hash && mgf.subs[0].toOID() === '1.2.840.113549.1.1.8' && hashes[mgf.subs[1].subs[0].toOID()] === hash, 'unsupported RSA-PSS hash');
    const saltLength = Number(integer(fields[2].subs[0], 128n));
    requireThat(fields.length === 3 || integer(fields[3].subs[0]) === 1n, 'unsupported RSA-PSS trailer');
    importAlgorithm = { name: 'RSA-PSS', hash }; verifyAlgorithm = { name: 'RSA-PSS', saltLength };
  } else if (oid === '1.2.840.10045.4.3.2' || oid === '1.2.840.10045.4.3.3') {
    const hash = oid.endsWith('.2') ? 'SHA-256' : 'SHA-384';
    const namedCurve = oid.endsWith('.2') ? 'P-256' : 'P-384';
    importAlgorithm = { name: 'ECDSA', namedCurve }; verifyAlgorithm = { name: 'ECDSA', hash };
    const rs = der(signature);
    requireThat(rs.tag.toDER() === 0x30 && rs.subs.length === 2, 'invalid ECDSA signature');
    const size = namedCurve === 'P-256' ? 32 : 48;
    sig = new Uint8Array(size * 2);
    rs.subs.forEach((part, i) => {
      const n = integer(part, (1n << BigInt(size * 8)) - 1n);
      sig.set(unhex(n.toString(16).padStart(size * 2, '0')), i * size);
    });
  } else {
    throw new Error(`unsupported certificate signature algorithm ${oid}`);
  }
  const key = await crypto.subtle.importKey('spki', buffer(issuer.publicKey), importAlgorithm, false, ['verify']);
  requireThat(await crypto.subtle.verify(verifyAlgorithm, key, buffer(sig), buffer(data)), 'invalid certificate or CRL signature');
}
export function checkTime(start: Date, end: Date, now: Date, label: string): void {
  requireThat(Number.isFinite(start.getTime()) && Number.isFinite(end.getTime()) && Number.isFinite(now.getTime()) && start <= now && now <= end, `${label} is outside its validity window`);
}
function usage(cert: X509Certificate, bit: number): void {
  const value = cert.extension('2.5.29.15');
  // RFC 5280: absence of KeyUsage does not constrain the key.
  requireThat(!value || der(value.value).toBitString()[bit] === 1, 'certificate key usage does not permit operation');
}
export async function verifyChain(chain: X509Certificate[], anchors: X509Certificate[], now: Date, leafUsage = 0): Promise<void> {
  requireThat(chain.length >= 2 && anchors.some(a => equal(a.root.toDER(), chain[chain.length - 1].root.toDER())), 'certificate chain does not end at a pinned root');
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i], issuer = chain[Math.min(i + 1, chain.length - 1)];
    checkTime(cert.notBefore, cert.notAfter, now, 'certificate');
    requireThat(equal(cert.issuer, issuer.subject), 'certificate issuer mismatch');
    if (i === 0) usage(cert, leafUsage);
    if (i > 0) {
      const bc = cert.extension('2.5.29.19');
      const b = bc && der(bc.value);
      requireThat(b && b.subs.length > 0 && b.subs[0].toBoolean(), 'certificate issuer is not a CA');
      if (b.subs[1]) requireThat(integer(b.subs[1]) >= BigInt(i - 1), 'certificate path length exceeded');
      usage(cert, 5);
    }
    try { await verifySigned(issuer, cert.root.subs[1], cert.signatureValue, cert.tbsCertificate.toDER()); }
    catch (cause) { throw new Error(`certificate signature verification failed for ${cert.subjectDN.get('CN')}: ${cause instanceof Error ? cause.message : String(cause)}`); }
  }
}
function validateCRLExtensions(extensions: ASN1Obj): void {
  requireThat(extensions.tag.toDER() === 0x30 && extensions.subs.length > 0, 'invalid CRL extensions');
  for (const ext of extensions.subs) {
    const fields = ext.subs;
    requireThat(ext.tag.toDER() === 0x30 && (fields.length === 2 || fields.length === 3) &&
      fields[0].tag.toDER() === 0x06 && fields[fields.length - 1].tag.toDER() === 0x04 &&
      (fields.length === 2 || fields[1].tag.isBoolean()), 'invalid CRL extension structure');
    requireThat(fields.length === 2 || !fields[1].toBoolean(), 'unsupported critical CRL extension');
  }
}
export async function verifyCRL(bytes: Uint8Array, issuer: X509Certificate, now: Date, subjects: X509Certificate[]): Promise<void> {
  const crl = der(bytes);
  requireThat(crl.tag.toDER() === 0x30 && crl.subs.length === 3, 'invalid CRL');
  const tbs = crl.subs[0], fields = tbs.subs;
  let i = 0;
  if (fields[i].tag.isInteger()) requireThat(integer(fields[i++]) === 1n, 'unsupported CRL version');
  requireThat(equal(fields[i++].toDER(), crl.subs[1].toDER()), 'CRL signature algorithms differ');
  requireThat(equal(fields[i++].value, issuer.subject), 'CRL issuer mismatch');
  checkTime(fields[i++].toDate(), fields[i++].toDate(), now, 'CRL');
  usage(issuer, 6);
  requireThat(crl.subs[2].tag.isBitString() && crl.subs[2].value[0] === 0, 'invalid CRL signature bit string');
  await verifySigned(issuer, crl.subs[1], crl.subs[2].value.slice(1), tbs.toDER());
  if (fields[i]?.tag.toDER() === 0x30) {
    for (const entry of fields[i++].subs) {
      requireThat(entry.tag.toDER() === 0x30 && (entry.subs.length === 2 || entry.subs.length === 3), 'invalid revoked certificate entry');
      if (entry.subs[2]) validateCRLExtensions(entry.subs[2]);
      const serial = integer(entry.subs[0], (1n << 160n) - 1n);
      requireThat(!subjects.some(s => BigInt('0x' + hex(s.serialNumber)) === serial), 'certificate is revoked');
    }
  }
  if (fields[i]) {
    requireThat(fields[i].tag.toDER() === 0xa0 && fields[i].subs.length === 1, 'invalid CRL extensions');
    validateCRLExtensions(fields[i++].subs[0]);
  }
  requireThat(i === fields.length, 'unexpected CRL data');
}
export async function verifyEC(key: CryptoKey, signature: Uint8Array, data: Uint8Array, hash = 'SHA-256'): Promise<void> {
  requireThat(await crypto.subtle.verify({ name: 'ECDSA', hash }, key, buffer(signature), buffer(data)), 'invalid ECDSA signature');
}
