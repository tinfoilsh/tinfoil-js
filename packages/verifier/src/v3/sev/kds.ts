// AMD Key Distribution Service V[CL]EK certificate extensions, ported 1:1
// from github.com/google/go-sev-guest kds. All errors are plain Errors; the
// calling module assigns the rejection layer.

import { bytesToLatin1 } from "../bytes.js";
import {
  productLineToTCBVersion,
  reportSignerString,
  TcbStructVersion0,
  TcbStructVersion1,
  tcbPartsToVersion,
  VcekReportSigner,
  VlekReportSigner,
  NoneReportSigner,
} from "./abi.js";
import { decodeUint, readTLV, type Extension } from "../der.js";
import { oidAuthorityKeyID, type Certificate } from "./x509.js";

// HWID extension lengths per TCB struct version.
const HwidLenVersion0 = 64; // Genoa
const HwidLenVersion1 = 8; // Turin (PSN-based)

// KDS x509v3 extension OIDs.
export const OidStructVersion = "1.3.6.1.4.1.3704.1.1";
export const OidProductName1 = "1.3.6.1.4.1.3704.1.2";
export const OidBlSpl = "1.3.6.1.4.1.3704.1.3.1";
export const OidTeeSpl = "1.3.6.1.4.1.3704.1.3.2";
export const OidSnpSpl = "1.3.6.1.4.1.3704.1.3.3";
export const OidSpl4 = "1.3.6.1.4.1.3704.1.3.4";
export const OidSpl5 = "1.3.6.1.4.1.3704.1.3.5";
export const OidSpl6 = "1.3.6.1.4.1.3704.1.3.6";
export const OidSpl7 = "1.3.6.1.4.1.3704.1.3.7";
export const OidUcodeSpl = "1.3.6.1.4.1.3704.1.3.8";
export const OidFmcSpl = "1.3.6.1.4.1.3704.1.3.9";
export const OidHwid = "1.3.6.1.4.1.3704.1.4";
export const OidCspID = "1.3.6.1.4.1.3704.1.5";

const kdsOids = new Set([
  OidStructVersion,
  OidProductName1,
  OidBlSpl,
  OidTeeSpl,
  OidSnpSpl,
  OidSpl4,
  OidSpl5,
  OidSpl6,
  OidSpl7,
  OidUcodeSpl,
  OidFmcSpl,
  OidHwid,
  OidCspID,
]);

// Extensions represents the KDS-specified x509 extensions of a V[CL]EK
// certificate (Go kds.Extensions). tcbStructVersion tags the tcbVersion
// layout; hwid is 64 bytes for struct version 0, 8 bytes for version 1.
export interface KDSExtensions {
  structVersion: number;
  productName: string;
  hwid: Uint8Array | undefined;
  tcbStructVersion: number;
  tcbVersion: bigint;
  cspID: string;
}

// kdsOidMap indexes the certificate's extensions by KDS OID, rejecting
// non-KDS extensions (the authority key id is imparted by signing and
// skipped) and duplicates (Go kds.kdsOidMap).
function kdsOidMap(cert: Certificate): Map<string, Extension> {
  const result = new Map<string, Extension>();
  for (const ext of cert.extensions) {
    if (ext.oid === oidAuthorityKeyID) continue;
    if (!kdsOids.has(ext.oid)) {
      throw new Error(`not an AMD KDS OID: ${ext.oid}`);
    }
    if (result.has(ext.oid)) {
      throw new Error(`duplicate AMD KDS extension: ${ext.oid}`);
    }
    result.set(ext.oid, ext);
  }
  return result;
}

// asn1U8 parses an extension value as a DER INTEGER in 0-255 (Go kds.asn1U8).
function asn1U8(ext: Extension | undefined, field: string): number {
  if (ext === undefined) throw new Error(`no extension for field ${field}`);
  const t = readTLV(ext.value, 0);
  if (t.cls !== 0 || t.tag !== 0x02) {
    throw new Error(`could not parse extension as an integer: field ${field}`);
  }
  if (t.end !== ext.value.length) {
    throw new Error(`unexpected leftover bytes for U8 field ${field}`);
  }
  const i = decodeUint(ext.value.subarray(t.contentStart, t.end), field);
  if (i > 255) throw new Error(`int value for field ${field} isn't a uint8: ${i}`);
  return i;
}

// asn1IA5String parses an extension value as an IA5String (Go kds.asn1IA5String).
function asn1IA5String(ext: Extension | undefined, field: string): string {
  if (ext === undefined || ext.value.length === 0) throw new Error(`no extension for field ${field}`);
  if (ext.value[0] !== 0x16) {
    throw new Error(`value is not tagged as an IA5String: ${ext.value[0]}`);
  }
  const t = readTLV(ext.value, 0);
  if (t.end !== ext.value.length) {
    throw new Error(`unexpected leftover bytes for IA5String field ${field}`);
  }
  return bytesToLatin1(ext.value.subarray(t.contentStart, t.end));
}

// asn1OctetString accepts the KDS HWID both raw (the KDS omits the type tag)
// and as a proper OCTET STRING (Go kds.asn1OctetString).
function asn1OctetString(ext: Extension | undefined, field: string, size: number): Uint8Array {
  if (ext === undefined) throw new Error(`no extension for field ${field}`);
  if (ext.value.length === size) return ext.value;
  const t = readTLV(ext.value, 0);
  if (t.cls !== 0 || t.tag !== 0x04) {
    throw new Error(`could not parse extension as an octet string: field ${field}`);
  }
  if (t.end !== ext.value.length) {
    throw new Error(`expected leftover bytes in extension value for field ${field}`);
  }
  const octet = ext.value.subarray(t.contentStart, t.end);
  if (size >= 0 && octet.length !== size) {
    throw new Error(`size is ${octet.length}, expected ${size}`);
  }
  return octet;
}

function kdsOidMapToExtensions(exts: Map<string, Extension>): KDSExtensions {
  const structVersion = asn1U8(exts.get(OidStructVersion), "StructVersion");
  const productName = asn1IA5String(exts.get(OidProductName1), "ProductName1");
  let hwidLen: number;
  if (structVersion === TcbStructVersion0) {
    hwidLen = HwidLenVersion0;
  } else if (structVersion === TcbStructVersion1) {
    hwidLen = HwidLenVersion1;
  } else {
    throw new Error(`unsupported TCB structVersion ${structVersion}`);
  }

  let hwid: Uint8Array | undefined;
  const hwidExt = exts.get(OidHwid);
  if (hwidExt !== undefined) {
    hwid = asn1OctetString(hwidExt, "HWID", hwidLen);
  }
  let cspID = "";
  const cspidExt = exts.get(OidCspID);
  if (cspidExt !== undefined) {
    cspID = asn1IA5String(cspidExt, "CSP_ID");
    if (hwidExt !== undefined) {
      throw new Error("certificate has both HWID and CSP_ID extensions");
    }
  }

  const blSpl = asn1U8(exts.get(OidBlSpl), "BlSpl");
  const teeSpl = asn1U8(exts.get(OidTeeSpl), "TeeSpl");
  const snpSpl = asn1U8(exts.get(OidSnpSpl), "SnpSpl");
  const spl5 = asn1U8(exts.get(OidSpl5), "Spl5");
  const spl6 = asn1U8(exts.get(OidSpl6), "Spl6");
  const spl7 = asn1U8(exts.get(OidSpl7), "Spl7");
  const ucodeSpl = asn1U8(exts.get(OidUcodeSpl), "UcodeSpl");

  let spl4 = 0;
  let fmcSpl = 0;
  if (structVersion === TcbStructVersion0) {
    if (exts.has(OidFmcSpl)) {
      throw new Error("FmcSpl extension is not valid for TCB struct version 0");
    }
    spl4 = asn1U8(exts.get(OidSpl4), "Spl4");
  } else {
    if (exts.has(OidSpl4)) {
      throw new Error("Spl4 extension is not valid for TCB struct version 1");
    }
    fmcSpl = asn1U8(exts.get(OidFmcSpl), "FmcSpl");
  }

  const { structVersion: tcbStructVersion, tcb: tcbVersion } = tcbPartsToVersion({
    version: structVersion,
    blSpl,
    teeSpl,
    snpSpl,
    spl4,
    spl5,
    spl6,
    spl7,
    ucodeSpl,
    fmcSpl,
  });
  return { structVersion, productName, hwid, tcbStructVersion, tcbVersion, cspID };
}

// vcekCertificateExtensions returns the KDS extensions of a VCEK certificate
// (Go kds.VcekCertificateExtensions).
export function vcekCertificateExtensions(cert: Certificate): KDSExtensions {
  const exts = kdsOidMapToExtensions(kdsOidMap(cert));
  if (exts.cspID !== "") {
    throw new Error(`unexpected CSP_ID in VCEK certificate: ${exts.cspID}`);
  }
  if (exts.hwid === undefined || (exts.hwid.length !== HwidLenVersion0 && exts.hwid.length !== HwidLenVersion1)) {
    throw new Error("missing HWID extension for VCEK certificate");
  }
  return exts;
}

// vlekCertificateExtensions returns the KDS extensions of a VLEK certificate
// (Go kds.VlekCertificateExtensions).
export function vlekCertificateExtensions(cert: Certificate): KDSExtensions {
  const exts = kdsOidMapToExtensions(kdsOidMap(cert));
  if (exts.cspID === "") {
    throw new Error("missing CSP_ID in VLEK certificate");
  }
  if (exts.hwid !== undefined) {
    throw new Error("unexpected HWID in VLEK certificate");
  }
  return exts;
}

// certificateExtensions dispatches on the report signer kind (Go
// kds.CertificateExtensions).
export function certificateExtensions(cert: Certificate, key: number): KDSExtensions {
  switch (key) {
    case VcekReportSigner:
      return vcekCertificateExtensions(cert);
    case VlekReportSigner:
      return vlekCertificateExtensions(cert);
    case NoneReportSigner:
      return {
        structVersion: 0,
        productName: "",
        hwid: undefined,
        tcbStructVersion: TcbStructVersion0,
        tcbVersion: 0n,
        cspID: "",
      };
  }
  throw new Error(`unexpected endorsement key kind ${reportSignerString(key)}`);
}

// validateExtensions requires the certificate's TCB format to match the known
// product line's; the product-name claim itself is disregarded (Go
// verify.validateExtensions for knownProductLine != "").
export function validateExtensions(exts: KDSExtensions, productLine: string): void {
  let expected: number;
  try {
    expected = productLineToTCBVersion(productLine);
  } catch {
    throw new Error(`could not determine TCB format for product "${productLine}"`);
  }
  if (expected !== exts.tcbStructVersion) {
    throw new Error(`product "${productLine}" and V[CL]EK certificate use different TCB formats`);
  }
}
