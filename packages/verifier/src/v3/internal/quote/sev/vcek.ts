/**
 * The VCEK certificate: the AMD Key Distribution Service shape (RSA-PSS
 * SHA-384 signed, P-384 key, AMD subject with CN SEV-VCEK, issued by the
 * product's SEV-<product> signing key) and its private extensions, which
 * carry the hardware id and the TCB the certificate is endorsed for.
 */
import {
  expectSequence,
  isUniversal,
  parseCertificate,
  verifyChain,
  X509Error,
  type Certificate,
  type Extension,
} from "../../x509/certificate.js";
import { children, decode, DerError, integer, oid, pemBlocks, TAG, type DerElement } from "../../x509/der.js";
import type { ProductLine } from "./report.js";
import { composeTcb, TCB_LAYOUT_0, TCB_LAYOUT_1, tcbLayoutOf, type TcbLayout, type TcbParts } from "./tcb.js";

const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_P384 = "1.3.132.0.34";
const OID_AUTHORITY_KEY_ID = "2.5.29.35";

const OID_COUNTRY = "2.5.4.6";
const OID_STATE = "2.5.4.8";
const OID_LOCALITY = "2.5.4.7";
const OID_ORGANIZATION = "2.5.4.10";
const OID_ORGANIZATIONAL_UNIT = "2.5.4.11";
const OID_COMMON_NAME = "2.5.4.3";

const KDS = "1.3.6.1.4.1.3704.1.";
const OID_STRUCT_VERSION = `${KDS}1`;
const OID_PRODUCT_NAME = `${KDS}2`;
const OID_BL_SPL = `${KDS}3.1`;
const OID_TEE_SPL = `${KDS}3.2`;
const OID_SNP_SPL = `${KDS}3.3`;
const OID_SPL4 = `${KDS}3.4`;
const OID_SPL5 = `${KDS}3.5`;
const OID_SPL6 = `${KDS}3.6`;
const OID_SPL7 = `${KDS}3.7`;
const OID_UCODE_SPL = `${KDS}3.8`;
const OID_FMC_SPL = `${KDS}3.9`;
const OID_HWID = `${KDS}4`;
const OID_CSP_ID = `${KDS}5`;
const KDS_OIDS: ReadonlySet<string> = new Set([
  OID_STRUCT_VERSION,
  OID_PRODUCT_NAME,
  OID_BL_SPL,
  OID_TEE_SPL,
  OID_SNP_SPL,
  OID_SPL4,
  OID_SPL5,
  OID_SPL6,
  OID_SPL7,
  OID_UCODE_SPL,
  OID_FMC_SPL,
  OID_HWID,
  OID_CSP_ID,
]);

const HWID_SIZE_LAYOUT_0 = 64;
const HWID_SIZE_LAYOUT_1 = 8;

/** What the VCEK's private extensions state. */
export interface VcekExtensions {
  readonly productName: string;
  /** 64 bytes under TCB layout 0, 8 under layout 1. */
  readonly hwid: Uint8Array;
  readonly tcb: TcbParts;
}

/** The trusted signing-key and root certificates of a product line. */
export interface AmdRoots {
  readonly ask: Certificate;
  readonly ark: Certificate;
}

/** Parses an AMD KDS cert_chain: exactly the ASK then the ARK as PEM CERTIFICATE blocks. */
export function parseAmdRoots(pem: string): AmdRoots {
  const blocks = pemBlocks(pem, "CERTIFICATE");
  if (blocks.length !== 2) throw new Error(`AMD root chain must carry exactly the ASK and ARK certificates, got ${blocks.length} blocks`);
  return { ask: parseCertificate(blocks[0]), ark: parseCertificate(blocks[1]) };
}

/**
 * Checks the document-carried ASK+ARK chain's shape: exactly two non-empty
 * CERTIFICATE blocks and nothing else. The chain is untrusted transport;
 * verification uses the pinned roots, so its contents are not read.
 */
export function checkCertChainShape(chainPem: string): void {
  const lines = chainPem.split(/\r?\n/);
  let blocks = 0;
  let inside = false;
  let bodyLines = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (line === "") continue;
    if (!inside) {
      if (line === "-----BEGIN CERTIFICATE-----") {
        inside = true;
        bodyLines = 0;
      } else if (line.startsWith("-----BEGIN ")) {
        throw new Error(`cert_chain_pem carries a ${JSON.stringify(line.slice(11, -5))} block, want CERTIFICATE`);
      } else {
        throw new Error("cert_chain_pem carries data outside its certificates");
      }
    } else if (line === "-----END CERTIFICATE-----") {
      if (bodyLines === 0) throw new Error("cert_chain_pem carries an empty CERTIFICATE block");
      inside = false;
      blocks++;
    } else {
      bodyLines++;
    }
  }
  if (inside) throw new Error("cert_chain_pem carries an unterminated CERTIFICATE block");
  if (blocks !== 2) throw new Error(`cert_chain_pem must carry exactly the ASK and ARK certificates, got ${blocks} blocks`);
}

/** The string values of one attribute type across every RDN of a DER Name. */
function attributeValues(nameDer: Uint8Array, type: string): string[] {
  const out: string[] = [];
  for (const rdn of expectSequence(decode(nameDer), "Name")) {
    if (!isUniversal(rdn, TAG.SET)) throw new X509Error("Name must hold SETs of attributes");
    for (const atv of children(rdn)) {
      const parts = expectSequence(atv, "attribute");
      if (parts.length !== 2) throw new X509Error("attribute must be a type and a value");
      if (oid(parts[0]) !== type) continue;
      out.push(stringValue(parts[1]));
    }
  }
  return out;
}

function stringValue(v: DerElement): string {
  if (!isUniversal(v, TAG.UTF8_STRING) && !isUniversal(v, TAG.PRINTABLE_STRING) && !isUniversal(v, TAG.IA5_STRING)) {
    throw new X509Error("name attribute is not a string");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(v.value);
  } catch {
    throw new X509Error("name attribute is not valid UTF-8");
  }
}

/** Requires the AMD location attributes, each exactly once, and the given common name. */
function checkAmdName(nameDer: Uint8Array, role: string, commonName: string): void {
  const expect = (type: string, what: string, value: string): void => {
    const values = attributeValues(nameDer, type);
    if (values.length !== 1) throw new Error(`${role} has ${values.length} ${what} attributes, want 1`);
    if (values[0] !== value) throw new Error(`${role} ${what} ${JSON.stringify(values[0])} is not ${JSON.stringify(value)}`);
  };
  expect(OID_COUNTRY, "country", "US");
  expect(OID_LOCALITY, "locality", "Santa Clara");
  expect(OID_STATE, "state", "CA");
  expect(OID_ORGANIZATION, "organization", "Advanced Micro Devices");
  expect(OID_ORGANIZATIONAL_UNIT, "organizational unit", "Engineering");
  expect(OID_COMMON_NAME, "common name", commonName);
}

function isP384Key(spki: Uint8Array): boolean {
  try {
    const parts = expectSequence(decode(spki), "SubjectPublicKeyInfo");
    if (parts.length !== 2) return false;
    const alg = expectSequence(parts[0], "key AlgorithmIdentifier");
    return alg.length === 2 && oid(alg[0]) === OID_EC_PUBLIC_KEY && oid(alg[1]) === OID_P384;
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) return false;
    throw err;
  }
}

function u8Extension(exts: Map<string, Extension>, id: string, field: string): number {
  const ext = exts.get(id);
  if (ext === undefined) throw new Error(`VCEK certificate has no ${field} extension`);
  let value: bigint;
  try {
    const el = decode(ext.value);
    if (!isUniversal(el, TAG.INTEGER)) throw new Error("not an INTEGER");
    value = integer(el);
  } catch (err) {
    throw new Error(`VCEK ${field} extension is not an INTEGER: ${(err as Error).message}`);
  }
  if (value < 0n || value > 255n) throw new Error(`VCEK ${field} extension value ${value} is not a uint8`);
  return Number(value);
}

function ia5Extension(exts: Map<string, Extension>, id: string, field: string): string {
  const ext = exts.get(id);
  if (ext === undefined || ext.value.length === 0) throw new Error(`VCEK certificate has no ${field} extension`);
  let el: DerElement;
  try {
    el = decode(ext.value);
  } catch (err) {
    throw new Error(`VCEK ${field} extension is malformed: ${(err as Error).message}`);
  }
  if (!isUniversal(el, TAG.IA5_STRING)) throw new Error(`VCEK ${field} extension is not an IA5String`);
  for (const b of el.value) if (b > 0x7f) throw new Error(`VCEK ${field} extension is not ASCII`);
  return new TextDecoder().decode(el.value);
}

/** The HWID: the extension value is the bare bytes, or an OCTET STRING of them. */
function hwidExtension(ext: Extension, size: number): Uint8Array {
  if (ext.value.length === size) return ext.value.slice();
  let el: DerElement;
  try {
    el = decode(ext.value);
  } catch (err) {
    throw new Error(`VCEK HWID extension is malformed: ${(err as Error).message}`);
  }
  if (!isUniversal(el, TAG.OCTET_STRING)) throw new Error("VCEK HWID extension is not an OCTET STRING");
  if (el.value.length !== size) throw new Error(`VCEK HWID is ${el.value.length} bytes, expected ${size}`);
  return el.value.slice();
}

/**
 * Reads the VCEK's private extensions. Every extension other than the
 * authority key identifier must be one of the KDS ones; the struct version
 * selects the TCB layout, which fixes the hardware id size and which level
 * extensions must or must not appear.
 */
export function parseVcekExtensions(cert: Certificate): VcekExtensions {
  const exts = new Map<string, Extension>();
  for (const ext of cert.extensions) {
    if (ext.oid === OID_AUTHORITY_KEY_ID) continue;
    if (!KDS_OIDS.has(ext.oid)) throw new Error(`VCEK certificate extension ${ext.oid} is not an AMD KDS extension`);
    exts.set(ext.oid, ext);
  }
  const structVersion = u8Extension(exts, OID_STRUCT_VERSION, "StructVersion");
  let layout: TcbLayout;
  let hwidSize: number;
  switch (structVersion) {
    case TCB_LAYOUT_0:
      layout = TCB_LAYOUT_0;
      hwidSize = HWID_SIZE_LAYOUT_0;
      break;
    case TCB_LAYOUT_1:
      layout = TCB_LAYOUT_1;
      hwidSize = HWID_SIZE_LAYOUT_1;
      break;
    default:
      throw new Error(`unsupported VCEK TCB struct version ${structVersion}`);
  }
  const productName = ia5Extension(exts, OID_PRODUCT_NAME, "ProductName");
  if (exts.has(OID_CSP_ID)) throw new Error("unexpected CSP_ID extension in VCEK certificate");
  const hwidExt = exts.get(OID_HWID);
  if (hwidExt === undefined) throw new Error("missing HWID extension for VCEK certificate");
  const hwid = hwidExtension(hwidExt, hwidSize);

  const blSpl = u8Extension(exts, OID_BL_SPL, "BlSpl");
  const teeSpl = u8Extension(exts, OID_TEE_SPL, "TeeSpl");
  const snpSpl = u8Extension(exts, OID_SNP_SPL, "SnpSpl");
  const spl5 = u8Extension(exts, OID_SPL5, "Spl5");
  const spl6 = u8Extension(exts, OID_SPL6, "Spl6");
  const spl7 = u8Extension(exts, OID_SPL7, "Spl7");
  const ucodeSpl = u8Extension(exts, OID_UCODE_SPL, "UcodeSpl");
  let spl4 = 0;
  let fmcSpl = 0;
  if (layout === TCB_LAYOUT_0) {
    if (exts.has(OID_FMC_SPL)) throw new Error("FmcSpl extension is not valid for TCB struct version 0");
    spl4 = u8Extension(exts, OID_SPL4, "Spl4");
  } else {
    if (exts.has(OID_SPL4)) throw new Error("Spl4 extension is not valid for TCB struct version 1");
    fmcSpl = u8Extension(exts, OID_FMC_SPL, "FmcSpl");
  }
  const tcb: TcbParts = { layout, blSpl, teeSpl, spl4, spl5, spl6, spl7, snpSpl, ucodeSpl, fmcSpl };
  composeTcb(tcb);
  return { productName, hwid, tcb };
}

/**
 * Checks the VCEK against the KDS shape for `product`: RSA-PSS SHA-384
 * signature, P-384 key, AMD subject named SEV-VCEK, private extensions in the
 * product's TCB layout, and an AMD issuer named for the product's signing key.
 */
export function checkVcekShape(cert: Certificate, product: ProductLine): VcekExtensions {
  if (cert.signatureAlgorithm !== "rsa-pss-sha384") {
    throw new Error(`VCEK certificate signature algorithm is ${cert.signatureAlgorithm}, expected SHA-384 with RSASSA-PSS`);
  }
  if (!isP384Key(cert.spki)) throw new Error("VCEK certificate public key is not ECDSA on P-384");
  checkAmdName(cert.subject, "VCEK subject", "SEV-VCEK");
  const exts = parseVcekExtensions(cert);
  if (exts.tcb.layout !== tcbLayoutOf(product)) {
    throw new Error(`product ${JSON.stringify(product)} and VCEK certificate use different TCB formats`);
  }
  checkAmdName(cert.issuer, "VCEK issuer", `SEV-${product}`);
  return exts;
}

/** Verifies VCEK → ASK → ARK at `now` against the pinned roots. */
export async function verifyVcekChain(vcek: Certificate, roots: AmdRoots, now: Date): Promise<void> {
  try {
    await verifyChain([vcek, roots.ask, roots.ark], [roots.ark], now);
  } catch (err) {
    if (err instanceof X509Error) throw new Error(`error verifying VCEK certificate: ${err.message}`);
    throw err;
  }
}
