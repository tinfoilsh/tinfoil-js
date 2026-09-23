// Intel TDX quote v4 ABI parsing, a 1:1 port of go-tdx-guest/abi (the subset
// QuoteToProto/CheckQuoteV4 exercise for quote v4). Slices out of range throw
// where Go would panic; every other condition mirrors the library's errors.
// All errors are plain Errors; the caller assigns the rejection layer.

// Sizes and offsets (abi.go constants).
export const QuoteMinSize = 0x3fc;
export const QuoteVersion = 4;
export const AttestationKeyType = 2; // ECDSA-256-with-P-256 curve
export const TeeTDX = 0x00000081;

const quoteHeaderEnd = 0x30;
const quoteBodyEnd = 0x278;
const quoteSignedDataSizeEnd = 0x27c;
const qeReportSize = 0x180;
const signatureSize = 0x40;
const attestationKeySize = 0x40;
const qeReportCertificationDataType = 0x6;
const pckReportCertificationDataType = 0x5;
const rtmrsCount = 4;
export const RtmrSize = 0x30;

export interface Header {
  version: number;
  attestationKeyType: number;
  teeType: number;
  qeSvn: Uint8Array; // reserved bytes 10-12 in quote v4
  pceSvn: Uint8Array; // reserved bytes 8-10 in quote v4
  qeVendorId: Uint8Array;
  userData: Uint8Array;
}

export interface TDQuoteBody {
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

export interface EnclaveReport {
  cpuSvn: Uint8Array;
  miscSelect: number;
  attributes: Uint8Array;
  mrEnclave: Uint8Array;
  mrSigner: Uint8Array;
  isvProdId: number;
  isvSvn: number;
  reportData: Uint8Array;
}

export interface QeAuthData {
  parsedDataSize: number;
  data: Uint8Array;
}

export interface PCKCertificateChainData {
  certificateDataType: number;
  size: number;
  pckCertChain: Uint8Array;
}

export interface QEReportCertificationData {
  qeReport: EnclaveReport;
  qeReportRaw: Uint8Array; // exact 384 signed bytes (EnclaveReportToAbiBytes)
  qeReportSignature: Uint8Array;
  qeAuthData: QeAuthData;
  pckCertificateChainData: PCKCertificateChainData;
}

export interface CertificationData {
  certificateDataType: number;
  size: number;
  qeReportCertificationData: QEReportCertificationData;
}

export interface Ecdsa256BitQuoteV4AuthData {
  signature: Uint8Array;
  ecdsaAttestationKey: Uint8Array;
  certificationData: CertificationData;
}

export interface QuoteV4 {
  header: Header;
  tdQuoteBody: TDQuoteBody;
  signedDataSize: number;
  signedData: Ecdsa256BitQuoteV4AuthData;
  extraBytes: Uint8Array;
  headerAndBody: Uint8Array; // exact signed region raw[0:0x278]
}

function slice(b: Uint8Array, start: number, end: number, what: string): Uint8Array {
  if (end > b.length || start > end) throw new Error(`${what}: quote data is truncated`);
  return b.subarray(start, end);
}

function u16le(b: Uint8Array, off: number, what: string): number {
  const s = slice(b, off, off + 2, what);
  return s[0] | (s[1] << 8);
}

function u32le(b: Uint8Array, off: number, what: string): number {
  const s = slice(b, off, off + 4, what);
  return (s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24)) >>> 0;
}

function headerToProto(data: Uint8Array): Header {
  const header: Header = {
    version: u16le(data, 0x00, "header version"),
    attestationKeyType: u16le(data, 0x02, "attestation key type"),
    teeType: u32le(data, 0x04, "tee type"),
    pceSvn: data.subarray(0x08, 0x0a),
    qeSvn: data.subarray(0x0a, 0x0c),
    qeVendorId: data.subarray(0x0c, 0x1c),
    userData: data.subarray(0x1c, 0x30),
  };
  checkHeader(header);
  return header;
}

function checkHeader(header: Header): void {
  if (header.version !== QuoteVersion) {
    throw new Error(`parsing header failed: version ${header.version} not supported`);
  }
  if (header.attestationKeyType !== AttestationKeyType) {
    throw new Error("parsing header failed: attestation key type not supported");
  }
  if (header.teeType !== TeeTDX) {
    throw new Error("parsing header failed: TEE type is not TDX");
  }
}

function tdQuoteBodyToProto(data: Uint8Array): TDQuoteBody {
  const rtmrs: Uint8Array[] = [];
  for (let i = 0; i < rtmrsCount; i++) {
    rtmrs.push(data.subarray(0x148 + i * RtmrSize, 0x148 + (i + 1) * RtmrSize));
  }
  return {
    teeTcbSvn: data.subarray(0x00, 0x10),
    mrSeam: data.subarray(0x10, 0x40),
    mrSignerSeam: data.subarray(0x40, 0x70),
    seamAttributes: data.subarray(0x70, 0x78),
    tdAttributes: data.subarray(0x78, 0x80),
    xfam: data.subarray(0x80, 0x88),
    mrTd: data.subarray(0x88, 0xb8),
    mrConfigId: data.subarray(0xb8, 0xe8),
    mrOwner: data.subarray(0xe8, 0x118),
    mrOwnerConfig: data.subarray(0x118, 0x148),
    rtmrs,
    reportData: data.subarray(0x208, 0x248),
  };
}

function enclaveReportToProto(data: Uint8Array): EnclaveReport {
  return {
    cpuSvn: data.subarray(0x00, 0x10),
    miscSelect: u32le(data, 0x10, "QE report miscSelect"),
    attributes: data.subarray(0x30, 0x40),
    mrEnclave: data.subarray(0x40, 0x60),
    mrSigner: data.subarray(0x80, 0xa0),
    isvProdId: u16le(data, 0x100, "QE report isvProdId"),
    isvSvn: u16le(data, 0x102, "QE report isvSvn"),
    reportData: data.subarray(0x140, 0x180),
  };
}

function qeAuthDataToProto(data: Uint8Array): { authData: QeAuthData; authDataEnd: number } {
  const parsedDataSize = u16le(data, 0x00, "QE AuthData size");
  const authDataEnd = 0x02 + parsedDataSize;
  return {
    authData: { parsedDataSize, data: slice(data, 0x02, authDataEnd, "QE AuthData") },
    authDataEnd,
  };
}

function pckCertificateChainToProto(data: Uint8Array): PCKCertificateChainData {
  const chain: PCKCertificateChainData = {
    certificateDataType: u16le(data, 0x00, "PCK chain data type"),
    size: u32le(data, 0x02, "PCK chain size"),
    pckCertChain: data.subarray(0x06),
  };
  if (chain.certificateDataType !== pckReportCertificationDataType) {
    throw new Error(
      `parsing PCK certification chain failed: PCK certificate chain data type invalid, got ${chain.certificateDataType}, expected ${pckReportCertificationDataType}`,
    );
  }
  if (chain.size !== chain.pckCertChain.length) {
    throw new Error(
      `parsing PCK certification chain failed: PCK certificate chain size is ${chain.pckCertChain.length}. Expected size ${chain.size}`,
    );
  }
  return chain;
}

function qeReportCertificationDataToProto(data: Uint8Array): QEReportCertificationData {
  const qeReportRaw = slice(data, 0x00, qeReportSize, "QE report");
  const qeReport = enclaveReportToProto(qeReportRaw);
  const qeReportSignature = slice(data, qeReportSize, qeReportSize + signatureSize, "QE report signature");
  const { authData, authDataEnd } = qeAuthDataToProto(data.subarray(0x1c0));
  const pckCertificateChainData = pckCertificateChainToProto(data.subarray(0x1c0 + authDataEnd));
  return { qeReport, qeReportRaw, qeReportSignature, qeAuthData: authData, pckCertificateChainData };
}

function certificationDataToProto(data: Uint8Array): CertificationData {
  const certificateDataType = u16le(data, 0x00, "certification data type");
  const size = u32le(data, 0x02, "certification data size");
  const rawCertificateData = data.subarray(0x06);
  if (rawCertificateData.length !== size) {
    throw new Error(`size of certificate data is 0x${rawCertificateData.length.toString(16)}. Expected size 0x${size.toString(16)}`);
  }
  if (certificateDataType !== qeReportCertificationDataType) {
    throw new Error(
      `parsing certification data failed: certification data type invalid, got ${certificateDataType}, expected ${qeReportCertificationDataType}`,
    );
  }
  return {
    certificateDataType,
    size,
    qeReportCertificationData: qeReportCertificationDataToProto(rawCertificateData),
  };
}

function signedDataToProto(data: Uint8Array): Ecdsa256BitQuoteV4AuthData {
  return {
    signature: slice(data, 0x00, 0x40, "quote signature"),
    ecdsaAttestationKey: slice(data, 0x40, 0x80, "attestation key"),
    certificationData: certificationDataToProto(data.subarray(0x80)),
  };
}

// quoteToProtoV4 parses the Intel ABI little-endian quote v4 byte layout
// (abi.QuoteToProto restricted to v4 — Go's wrapper rejects any other
// version, which determineQuoteFormat surfaces as an unsupported format).
export function quoteToProtoV4(b: Uint8Array): QuoteV4 {
  if (b.length < 2) {
    throw new Error("unable to determine quote format since bytes length is less than 2 bytes");
  }
  const version = b[0] | (b[1] << 8);
  if (version !== QuoteVersion) {
    throw new Error("quote format not supported");
  }
  if (b.length < QuoteMinSize) {
    throw new Error(
      `raw quote size is 0x${b.length.toString(16)}, a TDX quote should have size a minimum size of 0x${QuoteMinSize.toString(16)}`,
    );
  }
  const header = headerToProto(b.subarray(0, quoteHeaderEnd));
  const tdQuoteBody = tdQuoteBodyToProto(b.subarray(quoteHeaderEnd, quoteBodyEnd));
  const signedDataSize = u32le(b, quoteBodyEnd, "signed data size");
  const additionalData = b.subarray(quoteSignedDataSizeEnd);
  if (additionalData.length < signedDataSize) {
    throw new Error(
      `size of signed data is 0x${additionalData.length.toString(16)}. Expected minimum size of 0x${signedDataSize.toString(16)}`,
    );
  }
  const signedData = signedDataToProto(additionalData.subarray(0, signedDataSize));
  const extraBytes = additionalData.subarray(signedDataSize);
  return {
    header,
    tdQuoteBody,
    signedDataSize,
    signedData,
    extraBytes,
    headerAndBody: b.subarray(0, quoteBodyEnd),
  };
}
