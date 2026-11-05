/**
 * The TDX quote wire format, version 4: a 48-byte header, a 584-byte TD
 * report body, and signature data holding the ECDSA signature, the
 * attestation key, and the QE report certification data (type 6) that
 * wraps the QE report, its signature, the QE authentication data and the
 * PCK certificate chain (type 5). Every integer is little-endian. Lengths
 * are checked at every level, so a quote that overruns or underruns any of
 * its declared sizes rejects before anything is interpreted.
 */
import type { Register } from "../../../measurement.js";
import { pemBlocks } from "../../x509/der.js";

export const QUOTE_VERSION = 4;
export const ATTESTATION_KEY_TYPE_ECDSA_P256 = 2;
export const TEE_TYPE_TDX = 0x00000081;

const MIN_QUOTE_SIZE = 0x3fc;
const HEADER_SIZE = 48;
const BODY_SIZE = 584;
const SIGNED_SIZE = HEADER_SIZE + BODY_SIZE;
const SIGNATURE_SIZE = 64;
const ATTESTATION_KEY_SIZE = 64;
const QE_REPORT_SIZE = 384;
const CERTIFICATION_HEADER_SIZE = 6;
const QE_REPORT_CERTIFICATION_DATA_TYPE = 6;
const PCK_CERT_CHAIN_DATA_TYPE = 5;
export const REGISTER_SIZE = 48;
export const REPORT_DATA_SIZE = 64;
export const TEE_TCB_SVN_SIZE = 16;
export const QE_VENDOR_ID_SIZE = 16;

export interface TdxQuoteHeader {
  readonly version: number;
  readonly attestationKeyType: number;
  readonly teeType: number;
  /** Bytes 8-9, reserved in version 4. */
  readonly pceSvn: Uint8Array;
  /** Bytes 10-11, reserved in version 4. */
  readonly qeSvn: Uint8Array;
  readonly qeVendorId: Uint8Array;
  readonly userData: Uint8Array;
}

/** The TD report body the quote signs. */
export interface TdxQuoteBody {
  readonly teeTcbSvn: Uint8Array;
  readonly mrSeam: Uint8Array;
  readonly mrSignerSeam: Uint8Array;
  readonly seamAttributes: Uint8Array;
  readonly tdAttributes: Uint8Array;
  readonly xfam: Uint8Array;
  readonly mrTd: Register;
  readonly mrConfigId: Uint8Array;
  readonly mrOwner: Uint8Array;
  readonly mrOwnerConfig: Uint8Array;
  readonly rtmrs: readonly [Register, Register, Register, Register];
  readonly reportData: Uint8Array;
}

/** The quoting enclave's report, as the PCK certificate signs it. */
export interface QeReport {
  readonly cpuSvn: Uint8Array;
  readonly miscSelect: number;
  readonly attributes: Uint8Array;
  readonly mrEnclave: Uint8Array;
  readonly mrSigner: Uint8Array;
  readonly isvProdId: number;
  readonly isvSvn: number;
  readonly reportData: Uint8Array;
  /** The 384 bytes the QE report signature covers. */
  readonly raw: Uint8Array;
}

export interface ParsedQuote {
  readonly header: TdxQuoteHeader;
  readonly body: TdxQuoteBody;
  /** Header and body: the bytes the quote signature covers. */
  readonly signedBytes: Uint8Array;
  /** ECDSA P-256 signature, r then s. */
  readonly signature: Uint8Array;
  /** The attestation public key, X then Y. */
  readonly attestationKey: Uint8Array;
  readonly qeReport: QeReport;
  /** ECDSA P-256 signature over the QE report by the PCK certificate, r then s. */
  readonly qeReportSignature: Uint8Array;
  readonly qeAuthData: Uint8Array;
  /** The PCK certificate chain as carried: PEM text, leaf first. */
  readonly pckChainPem: string;
  /** Bytes after the signature data; a quote read from a fixed-size buffer carries zero padding. */
  readonly extraBytes: Uint8Array;
}

class Reader {
  readonly view: DataView;
  constructor(
    readonly bytes: Uint8Array,
    readonly what: string,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  need(at: number, n: number): void {
    if (at < 0 || n < 0 || at + n > this.bytes.length) throw new Error(`${this.what} is truncated`);
  }
  u16(at: number): number {
    this.need(at, 2);
    return this.view.getUint16(at, true);
  }
  u32(at: number): number {
    this.need(at, 4);
    return this.view.getUint32(at, true);
  }
  slice(at: number, n: number): Uint8Array {
    this.need(at, n);
    return this.bytes.slice(at, at + n);
  }
}

/** Decodes a version 4 quote with QE report certification data (type 6) wrapping a PCK chain (type 5); other versions and types reject. */
export function parseQuote(bytes: Uint8Array): ParsedQuote {
  const r = new Reader(bytes, "TDX quote");
  const version = r.u16(0);
  if (version !== QUOTE_VERSION) throw new Error(`unsupported TDX quote version ${version}`);
  if (bytes.length < MIN_QUOTE_SIZE) throw new Error(`TDX quote is ${bytes.length} bytes, shorter than the minimum ${MIN_QUOTE_SIZE}`);
  const header: TdxQuoteHeader = {
    version,
    attestationKeyType: r.u16(2),
    teeType: r.u32(4),
    pceSvn: r.slice(8, 2),
    qeSvn: r.slice(10, 2),
    qeVendorId: r.slice(12, QE_VENDOR_ID_SIZE),
    userData: r.slice(28, 20),
  };
  if (header.attestationKeyType !== ATTESTATION_KEY_TYPE_ECDSA_P256) {
    throw new Error(`unsupported TDX attestation key type ${header.attestationKeyType}`);
  }
  if (header.teeType !== TEE_TYPE_TDX) throw new Error(`TEE type 0x${header.teeType.toString(16)} is not TDX`);

  const b = HEADER_SIZE;
  const body: TdxQuoteBody = {
    teeTcbSvn: r.slice(b, TEE_TCB_SVN_SIZE),
    mrSeam: r.slice(b + 0x10, 48),
    mrSignerSeam: r.slice(b + 0x40, 48),
    seamAttributes: r.slice(b + 0x70, 8),
    tdAttributes: r.slice(b + 0x78, 8),
    xfam: r.slice(b + 0x80, 8),
    mrTd: r.slice(b + 0x88, REGISTER_SIZE),
    mrConfigId: r.slice(b + 0xb8, 48),
    mrOwner: r.slice(b + 0xe8, 48),
    mrOwnerConfig: r.slice(b + 0x118, 48),
    rtmrs: [r.slice(b + 0x148, REGISTER_SIZE), r.slice(b + 0x178, REGISTER_SIZE), r.slice(b + 0x1a8, REGISTER_SIZE), r.slice(b + 0x1d8, REGISTER_SIZE)],
    reportData: r.slice(b + 0x208, REPORT_DATA_SIZE),
  };

  const signedDataSize = r.u32(SIGNED_SIZE);
  const signedStart = SIGNED_SIZE + 4;
  if (bytes.length - signedStart < signedDataSize) {
    throw new Error(`TDX quote declares ${signedDataSize} bytes of signature data but carries ${bytes.length - signedStart}`);
  }
  const signed = new Reader(bytes.subarray(signedStart, signedStart + signedDataSize), "TDX quote signature data");
  const extraBytes = bytes.slice(signedStart + signedDataSize);

  const signature = signed.slice(0, SIGNATURE_SIZE);
  const attestationKey = signed.slice(SIGNATURE_SIZE, ATTESTATION_KEY_SIZE);
  const certAt = SIGNATURE_SIZE + ATTESTATION_KEY_SIZE;
  const certType = signed.u16(certAt);
  const certSize = signed.u32(certAt + 2);
  if (certType !== QE_REPORT_CERTIFICATION_DATA_TYPE) {
    throw new Error(`TDX quote certification data is type ${certType}, expected ${QE_REPORT_CERTIFICATION_DATA_TYPE} (QE report)`);
  }
  const certData = signed.bytes.subarray(certAt + CERTIFICATION_HEADER_SIZE);
  if (certData.length !== certSize) {
    throw new Error(`TDX quote certification data is ${certData.length} bytes, declared ${certSize}`);
  }
  const cert = new Reader(certData, "TDX quote QE report certification data");
  const qeReport = parseQeReport(cert.slice(0, QE_REPORT_SIZE));
  const qeReportSignature = cert.slice(QE_REPORT_SIZE, SIGNATURE_SIZE);
  const authAt = QE_REPORT_SIZE + SIGNATURE_SIZE;
  const authSize = cert.u16(authAt);
  const qeAuthData = cert.slice(authAt + 2, authSize);
  const chainAt = authAt + 2 + authSize;
  const chainType = cert.u16(chainAt);
  const chainSize = cert.u32(chainAt + 2);
  if (chainType !== PCK_CERT_CHAIN_DATA_TYPE) {
    throw new Error(`TDX quote QE certification data is type ${chainType}, expected ${PCK_CERT_CHAIN_DATA_TYPE} (PCK certificate chain)`);
  }
  const chain = certData.subarray(chainAt + CERTIFICATION_HEADER_SIZE);
  if (chain.length !== chainSize) throw new Error(`TDX quote PCK certificate chain is ${chain.length} bytes, declared ${chainSize}`);

  return {
    header,
    body,
    signedBytes: bytes.slice(0, SIGNED_SIZE),
    signature,
    attestationKey,
    qeReport,
    qeReportSignature,
    qeAuthData,
    pckChainPem: chainText(chain),
    extraBytes,
  };
}

function parseQeReport(raw: Uint8Array): QeReport {
  const r = new Reader(raw, "QE report");
  return {
    cpuSvn: r.slice(0, 16),
    miscSelect: r.u32(16),
    attributes: r.slice(0x30, 16),
    mrEnclave: r.slice(0x40, 32),
    mrSigner: r.slice(0x80, 32),
    isvProdId: r.u16(0x100),
    isvSvn: r.u16(0x102),
    reportData: r.slice(0x140, REPORT_DATA_SIZE),
    raw,
  };
}

/** The chain bytes as text; a single trailing NUL, which some quoting enclaves append, is dropped. */
function chainText(chain: Uint8Array): string {
  const end = chain.length > 0 && chain[chain.length - 1] === 0 ? chain.length - 1 : chain.length;
  let text = "";
  for (let i = 0; i < end; i++) {
    const c = chain[i];
    if (c === 0 || c > 0x7e || (c < 0x20 && c !== 0x0a && c !== 0x0d && c !== 0x09)) {
      throw new Error("TDX quote PCK certificate chain is not PEM text");
    }
    text += String.fromCharCode(c);
  }
  return text;
}

/** The three DER certificates of the chain PEM, leaf first; any other count rejects. */
export function pckChainDer(pem: string): [Uint8Array, Uint8Array, Uint8Array] {
  const blocks = pemBlocks(pem, "CERTIFICATE");
  if (blocks.length !== 3) {
    throw new Error(`PCK certificate chain carries ${blocks.length} certificates, expected 3 (leaf, intermediate, root)`);
  }
  return [blocks[0], blocks[1], blocks[2]];
}
