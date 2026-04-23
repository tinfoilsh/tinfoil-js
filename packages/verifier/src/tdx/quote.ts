import {
  TDX_HEADER_SIZE,
  TDX_BODY_SIZE,
  TDX_SIGNED_DATA_SIZE_OFFSET,
  TDX_SIGNED_REGION_SIZE,
  TDX_MIN_QUOTE_SIZE,
  TDX_QUOTE_VERSION,
  TDX_ATTESTATION_KEY_TYPE,
  TDX_TEE_TYPE,
  INTEL_QE_VENDOR_ID,
  CERT_TYPE_QE_REPORT,
  PCK_CERT_CHAIN_TYPE,
  QE_REPORT_SIZE,
  ECDSA_P256_SIGNATURE_SIZE,
  ECDSA_P256_KEY_SIZE,
  RTMR_SIZE,
  RTMR_COUNT,
} from './constants.js';
import { AttestationError } from '../errors.js';
import { uint8ArrayEqual } from '@freedomofpress/crypto-browser';

export interface TdxQuoteHeader {
  version: number;
  attestationKeyType: number;
  teeType: number;
  qeVendorId: Uint8Array;
  userData: Uint8Array;
}

export interface TdQuoteBody {
  teeTcbSvn: Uint8Array;
  mrSeam: Uint8Array;
  mrSignerSeam: Uint8Array;
  seamAttributes: Uint8Array;
  tdAttributes: Uint8Array;
  xfam: Uint8Array;
  mrTd: Uint8Array;
  mrConfigId: Uint8Array;
  mrOwner: Uint8Array;
  mrOwnerConfig: Uint8Array;
  rtmrs: Uint8Array[];
  reportData: Uint8Array;
}

export interface QeReport {
  cpuSvn: Uint8Array;
  miscSelect: number;
  attributes: Uint8Array;
  mrEnclave: Uint8Array;
  mrSigner: Uint8Array;
  isvProdId: number;
  isvSvn: number;
  reportData: Uint8Array;
}

export interface TdxQuote {
  header: TdxQuoteHeader;
  body: TdQuoteBody;
  signedRegion: Uint8Array;
  signature: Uint8Array;
  attestationKey: Uint8Array;
  rawQeReportBytes: Uint8Array;
  qeReport: QeReport;
  qeReportSignature: Uint8Array;
  qeAuthData: Uint8Array;
  pckCertChain: string[];
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function parseHeader(data: Uint8Array): TdxQuoteHeader {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  const version = view.getUint16(0x00, true);
  if (version !== TDX_QUOTE_VERSION) {
    throw new AttestationError(
      `Invalid TDX quote version: ${version}. Only version ${TDX_QUOTE_VERSION} is supported`
    );
  }

  const attestationKeyType = view.getUint16(0x02, true);
  if (attestationKeyType !== TDX_ATTESTATION_KEY_TYPE) {
    throw new AttestationError(
      `Invalid attestation key type: ${attestationKeyType}. Expected ${TDX_ATTESTATION_KEY_TYPE} (ECDSA-256-with-P-256)`
    );
  }

  const teeType = view.getUint32(0x04, true);
  if (teeType !== TDX_TEE_TYPE) {
    throw new AttestationError(
      `Invalid TEE type: 0x${teeType.toString(16)}. Expected 0x${TDX_TEE_TYPE.toString(16)} (TDX)`
    );
  }

  const qeVendorId = data.slice(0x0C, 0x1C);
  if (!uint8ArrayEqual(qeVendorId, INTEL_QE_VENDOR_ID)) {
    throw new AttestationError(
      `Invalid QE Vendor ID: ${bytesToHex(qeVendorId)}. Expected Intel QE Vendor ID ${bytesToHex(INTEL_QE_VENDOR_ID)}`
    );
  }

  const userData = data.slice(0x1C, 0x30);

  return { version, attestationKeyType, teeType, qeVendorId, userData };
}

function parseBody(data: Uint8Array): TdQuoteBody {
  let offset = 0;

  const teeTcbSvn = data.slice(offset, offset + 16); offset += 16;
  const mrSeam = data.slice(offset, offset + 48); offset += 48;
  const mrSignerSeam = data.slice(offset, offset + 48); offset += 48;
  const seamAttributes = data.slice(offset, offset + 8); offset += 8;
  const tdAttributes = data.slice(offset, offset + 8); offset += 8;
  const xfam = data.slice(offset, offset + 8); offset += 8;
  const mrTd = data.slice(offset, offset + 48); offset += 48;
  const mrConfigId = data.slice(offset, offset + 48); offset += 48;
  const mrOwner = data.slice(offset, offset + 48); offset += 48;
  const mrOwnerConfig = data.slice(offset, offset + 48); offset += 48;

  const rtmrs: Uint8Array[] = [];
  for (let i = 0; i < RTMR_COUNT; i++) {
    rtmrs.push(data.slice(offset, offset + RTMR_SIZE));
    offset += RTMR_SIZE;
  }

  const reportData = data.slice(offset, offset + 64);

  return {
    teeTcbSvn, mrSeam, mrSignerSeam, seamAttributes,
    tdAttributes, xfam, mrTd, mrConfigId, mrOwner,
    mrOwnerConfig, rtmrs, reportData,
  };
}

function parseQeReport(data: Uint8Array): QeReport {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  return {
    cpuSvn: data.slice(0x000, 0x010),
    miscSelect: view.getUint32(0x010, true),
    attributes: data.slice(0x030, 0x040),
    mrEnclave: data.slice(0x040, 0x060),
    mrSigner: data.slice(0x080, 0x0A0),
    isvProdId: view.getUint16(0x100, true),
    isvSvn: view.getUint16(0x102, true),
    reportData: data.slice(0x140, 0x180),
  };
}

function parsePemCertificates(pemData: string): string[] {
  const certs: string[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match;
  while ((match = regex.exec(pemData)) !== null) {
    certs.push(match[0]);
  }
  return certs;
}

export function parseTdxQuote(rawQuote: Uint8Array): TdxQuote {
  if (rawQuote.length < TDX_MIN_QUOTE_SIZE) {
    throw new AttestationError(
      `TDX quote too small: ${rawQuote.length} bytes, minimum ${TDX_MIN_QUOTE_SIZE} bytes`
    );
  }

  const headerBytes = rawQuote.slice(0, TDX_HEADER_SIZE);
  const header = parseHeader(headerBytes);

  const bodyBytes = rawQuote.slice(TDX_HEADER_SIZE, TDX_HEADER_SIZE + TDX_BODY_SIZE);
  const body = parseBody(bodyBytes);

  const signedRegion = rawQuote.slice(0, TDX_SIGNED_REGION_SIZE);

  const sdView = new DataView(rawQuote.buffer, rawQuote.byteOffset, rawQuote.byteLength);
  const signedDataSize = sdView.getUint32(TDX_SIGNED_DATA_SIZE_OFFSET, true);

  const signedDataStart = TDX_SIGNED_DATA_SIZE_OFFSET + 4;
  if (rawQuote.length < signedDataStart + signedDataSize) {
    throw new AttestationError(
      `TDX quote truncated: signed data extends beyond buffer (need ${signedDataStart + signedDataSize}, have ${rawQuote.length})`
    );
  }

  let offset = signedDataStart;

  const signature = rawQuote.slice(offset, offset + ECDSA_P256_SIGNATURE_SIZE);
  offset += ECDSA_P256_SIGNATURE_SIZE;

  const attestationKey = rawQuote.slice(offset, offset + ECDSA_P256_KEY_SIZE);
  offset += ECDSA_P256_KEY_SIZE;

  // Certification data
  const certView = new DataView(rawQuote.buffer, rawQuote.byteOffset + offset, rawQuote.byteLength - offset);
  const certType = certView.getUint16(0, true);
  if (certType !== CERT_TYPE_QE_REPORT) {
    throw new AttestationError(
      `Invalid certification data type: ${certType}. Expected ${CERT_TYPE_QE_REPORT} (QE Report Certification Data)`
    );
  }

  const certDataSize = certView.getUint32(2, true);
  offset += 6;

  const certDataEnd = offset + certDataSize;
  if (rawQuote.length < certDataEnd) {
    throw new AttestationError('TDX quote truncated: certification data extends beyond buffer');
  }

  // QE Report (384 bytes)
  if (certDataSize < QE_REPORT_SIZE) {
    throw new AttestationError('TDX quote truncated: certification data too small for QE report');
  }
  const rawQeReportBytes = rawQuote.slice(offset, offset + QE_REPORT_SIZE);
  const qeReport = parseQeReport(rawQeReportBytes);
  offset += QE_REPORT_SIZE;

  // QE Report Signature (64 bytes)
  const qeReportSignature = rawQuote.slice(offset, offset + ECDSA_P256_SIGNATURE_SIZE);
  offset += ECDSA_P256_SIGNATURE_SIZE;

  // QE Auth Data
  const qaView = new DataView(rawQuote.buffer, rawQuote.byteOffset + offset, rawQuote.byteLength - offset);
  const qeAuthDataSize = qaView.getUint16(0, true);
  offset += 2;
  const qeAuthData = rawQuote.slice(offset, offset + qeAuthDataSize);
  offset += qeAuthDataSize;

  // PCK Cert Chain
  const pccView = new DataView(rawQuote.buffer, rawQuote.byteOffset + offset, rawQuote.byteLength - offset);
  const pckCertChainType = pccView.getUint16(0, true);
  if (pckCertChainType !== PCK_CERT_CHAIN_TYPE) {
    throw new AttestationError(
      `Invalid PCK cert chain type: ${pckCertChainType}. Expected ${PCK_CERT_CHAIN_TYPE}`
    );
  }
  const pckCertChainSize = pccView.getUint32(2, true);
  offset += 6;

  const pckCertChainRaw = rawQuote.slice(offset, offset + pckCertChainSize);
  // Remove null bytes that may be present in the PEM data
  const pckCertChainStr = new TextDecoder().decode(pckCertChainRaw).replace(/\0/g, '');
  const pckCertChain = parsePemCertificates(pckCertChainStr);

  if (pckCertChain.length < 2) {
    throw new AttestationError(
      `Invalid PCK cert chain: expected at least 2 certificates, got ${pckCertChain.length}`
    );
  }

  return {
    header,
    body,
    signedRegion,
    signature,
    attestationKey,
    rawQeReportBytes,
    qeReport,
    qeReportSignature,
    qeAuthData,
    pckCertChain,
  };
}
