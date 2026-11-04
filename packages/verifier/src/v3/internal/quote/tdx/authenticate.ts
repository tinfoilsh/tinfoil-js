/**
 * Intel TDX quotes (version 4): authentication of the quote's signature
 * chain to the Intel SGX root with the PCS collateral replayed from the
 * document, and the expectations a policy turns into.
 *
 * Authentication proves four things from the quote and the captured
 * collateral alone: the PCK certificate chain reaches the trusted root and
 * nothing in it is revoked; the TCB info and QE identity statements are
 * signed under that root and current; the attestation key is bound to the
 * QE report that the PCK certificate signs, and the quote body is signed by
 * that key; and the platform's TCB and quoting enclave are up to date by
 * Intel's statements. Nothing here compares the quote against a policy.
 */
import type { PcsResponse } from "../../../document/collateral/tdx.js";
import type { TdxMeasurement } from "../../../measurement.js";
import { INTEL_SGX_ROOT_CA_PEM } from "../../../trust/intel-sgx-root.js";
import { concat, sha256, toHex } from "../../bytes.js";
import { decodeHex } from "../../policy/artifact.js";
import { validateTdxPolicy, type TdxPolicy } from "../../policy/tdx.js";
import { bytesEqual, canSignData, parseCertificate, validAt, verifyChain, type Certificate, X509Error } from "../../x509/certificate.js";
import { isRevoked, parseRevocationList, verifyRevocationList } from "../../x509/crl.js";
import { DerError, pemBlocks } from "../../x509/der.js";
import { parseQuote, pckChainDer, REGISTER_SIZE, REPORT_DATA_SIZE, type ParsedQuote } from "./abi.js";
import { identity } from "./identity.js";
import { pckExtensions, type PckExtensions } from "./pck.js";
import {
  checkQeTcbStatus,
  checkTcbStatus,
  crlDistributionPointUris,
  indexCollateral,
  pckCrl,
  qeIdentity,
  QE_IDENTITY_ID,
  QE_IDENTITY_VERSION,
  rootCrl,
  TCB_INFO_ID,
  TCB_INFO_VERSION,
  tcbInfo,
  type PcsCollateral,
  type QeIdentity,
  type Statement,
  type TcbInfo,
} from "./pcs.js";

export { parseQuote } from "./abi.js";
export type { ParsedQuote, TdxQuoteBody, TdxQuoteHeader } from "./abi.js";

export const MR_CONFIG_ID_SIZE = 48;

const CN_ROOT = "Intel SGX Root CA";
const CN_PLATFORM_CA = "Intel SGX PCK Platform CA";
const CN_PCK = "Intel SGX PCK Certificate";
const CN_TCB_SIGNING = "Intel SGX TCB Signing";
const PCK_CA_PLATFORM = "platform";
const P256_SPKI_ALGORITHM = "ecdsa-p256-sha256";
const P256: EcKeyImportParams = { name: "ECDSA", namedCurve: "P-256" };

/** XFAM bits that must be set, and the only bits that may be set, in any accepted quote. */
const XFAM_FIXED1 = 0x00000003n;
const XFAM_FIXED0 = 0x0006dbe7n;
/** TD attribute bits that may be set: TUD.DEBUG, SEPT_VE_DISABLE, PKS and PERFMON. */
const TD_ATTRIBUTES_FIXED0 = 0x1n | (1n << 28n) | (1n << 30n) | (1n << 63n);

export interface TdxOptions {
  /** PEM root CA replacing the embedded Intel SGX root. Test-only. */
  readonly dangerousTestOnlyRoot?: Uint8Array;
}

export interface TdxEvidence {
  readonly quote: Uint8Array;
  readonly pcs: readonly PcsResponse[];
}

/** An authenticated quote. */
export interface TdxQuote {
  /** PPID, lowercase hex. */
  readonly identity: string;
  readonly measurement: TdxMeasurement;
  /** The lower of the TCB info's and QE identity's evaluation numbers used. */
  readonly tcbEvaluationDataNumber: bigint;
  readonly quote: ParsedQuote;
}

/** MRTD and RTMR0 as lowercase hex, for platform-measurement lookup. */
export function platformMeasurements(q: TdxQuote): { mrtd: string; rtmr0: string } {
  return { mrtd: toHex(q.quote.body.mrTd), rtmr0: toHex(q.quote.body.rtmrs[0]) };
}

/** The trusted Intel SGX root: the first certificate of the injected PEM, or the embedded root. */
function trustedRoot(opts: TdxOptions | undefined): Certificate {
  const pem = opts?.dangerousTestOnlyRoot === undefined ? INTEL_SGX_ROOT_CA_PEM : new TextDecoder("utf-8", { fatal: true }).decode(opts.dangerousTestOnlyRoot);
  try {
    const blocks = pemBlocks(pem, "CERTIFICATE");
    if (blocks.length === 0) throw new Error("Intel SGX root PEM carries no certificate");
    return parseCertificate(blocks[0]);
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`Intel SGX root certificate: ${err.message}`);
    throw err;
  }
}

/**
 * Authenticates a quote at `now`: version 4 with zero reserved SVN bytes and
 * only zero bytes after the signed data; the PCK chain to the trusted Intel
 * root, valid at `now`, with the root CA and PCK CRLs replayed from the
 * collateral, current at `now`, revoking neither certificate; the TCB info
 * and QE identity replayed from the collateral, signed under the root,
 * issued no later than `now` and not past their next update; the QE report
 * signed by the PCK certificate and binding the attestation key; the quote
 * body signed by that key; the platform's and the QE's TCB up to date. The
 * lower evaluation number of the two statements is recorded.
 */
export async function authenticateTdx(evidence: TdxEvidence, now: Date, opts?: TdxOptions): Promise<TdxQuote> {
  if (!Number.isFinite(now.getTime())) throw new Error("verification time is required");
  const root = trustedRoot(opts);
  const quote = parseQuote(evidence.quote);
  if (!isZero(quote.header.pceSvn) || !isZero(quote.header.qeSvn)) throw new Error("TDX quote header carries non-zero reserved bytes");
  if (!isZero(quote.extraBytes)) throw new Error("TDX quote carries non-zero bytes after the signed data");

  const chain = parseChain(quote.pckChainPem);
  const [leaf, intermediate] = chain;
  await verifyChain(chain, [root], now);
  if (!canSignData(leaf)) throw new Error("the PCK certificate's key usage does not permit signing");
  const pck = pckExtensions(leaf);

  const collateral = indexCollateral(evidence.pcs);
  const info = tcbInfo(collateral, toHex(pck.fmspc));
  const qe = qeIdentity(collateral);
  const crl = pckCrl(collateral, PCK_CA_PLATFORM);
  const rootCrlBody = rootCrl(collateral, crlDistributionPointUris(qe.root));
  const rootList = parseList(rootCrlBody, "root CA CRL");
  const pckList = parseList(crl.body, "PCK CRL");

  // Revocation: the root CA CRL covers the intermediate and the statement
  // signers, the PCK CRL covers the leaf. Each list must be current.
  await verifyRevocationList(rootList, root, now);
  await verifyRevocationList(pckList, intermediate, now);
  if (isRevoked(rootList, intermediate.serialNumber)) throw new Error("the PCK intermediate certificate is revoked");
  if (isRevoked(pckList, leaf.serialNumber)) throw new Error("the PCK certificate is revoked");
  for (const cert of [crl.signing, crl.root]) {
    if (!validAt(cert, now)) throw new Error("a PCK CRL issuer chain certificate is not valid at the verification time");
  }

  await verifyStatement(info, "tcbInfo", root, rootList, now);
  await verifyStatement(qe, "enclaveIdentity", root, rootList, now);
  checkTcbInfo(info.statement);
  checkQeIdentity(qe.statement);

  await verifySignatures(quote, leaf);
  checkQuoteBody(quote, info.statement, pck);
  checkQeReport(quote, qe.statement);

  const body = quote.body;
  const register = (r: Uint8Array): Uint8Array => {
    if (r.length !== REGISTER_SIZE) throw new Error(`TDX quote measurement registers must each be ${REGISTER_SIZE} bytes`);
    return r.slice();
  };
  const eval1 = info.statement.tcbEvaluationDataNumber;
  const eval2 = qe.statement.tcbEvaluationDataNumber;
  return {
    identity: identity(leaf),
    measurement: {
      platform: "tdx",
      mrtd: register(body.mrTd),
      rtmr0: register(body.rtmrs[0]),
      rtmr1: register(body.rtmrs[1]),
      rtmr2: register(body.rtmrs[2]),
      rtmr3: register(body.rtmrs[3]),
    },
    tcbEvaluationDataNumber: eval2 < eval1 ? eval2 : eval1,
    quote,
  };
}

function isZero(b: Uint8Array): boolean {
  return b.every((x) => x === 0);
}

/** The quote's chain as certificates, leaf first; each with its expected name and the P-256 signature algorithm. */
function parseChain(pem: string): [Certificate, Certificate, Certificate] {
  let certs: Certificate[];
  try {
    certs = pckChainDer(pem).map(parseCertificate);
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`PCK certificate chain: ${err.message}`);
    throw err;
  }
  const names = [CN_PCK, CN_PLATFORM_CA, CN_ROOT];
  certs.forEach((cert, i) => expectName(cert, names[i]));
  return [certs[0], certs[1], certs[2]];
}

function expectName(cert: Certificate, name: string): void {
  if (cert.subjectCommonName !== name) {
    throw new Error(`certificate ${JSON.stringify(cert.subjectCommonName ?? "")} is not the expected ${JSON.stringify(name)}`);
  }
  if (cert.signatureAlgorithm !== P256_SPKI_ALGORITHM) throw new Error(`${JSON.stringify(name)} is not signed with ECDSA P-256 and SHA-256`);
}

function parseList(der: Uint8Array, what: string) {
  try {
    return parseRevocationList(der);
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`${what}: ${err.message}`);
    throw err;
  }
}

/**
 * A statement's issuer chain is the TCB signing certificate under the
 * trusted root; the signing certificate is not revoked by the root CA CRL;
 * the signature covers the statement's exact bytes.
 */
async function verifyStatement<T extends { issueDate: Date; nextUpdate: Date; signed: Uint8Array; signature: Uint8Array }>(
  s: Statement<T>,
  what: string,
  root: Certificate,
  rootList: ReturnType<typeof parseRevocationList>,
  now: Date,
): Promise<void> {
  expectName(s.signing, CN_TCB_SIGNING);
  expectName(s.root, CN_ROOT);
  await verifyChain([s.signing, s.root], [root], now);
  if (!canSignData(s.signing)) throw new Error(`the ${what} signing certificate's key usage does not permit signing`);
  if (isRevoked(rootList, s.signing.serialNumber)) throw new Error(`the ${what} signing certificate is revoked`);
  if (!(await verifyP256(s.signing.spki, "spki", s.statement.signed, s.statement.signature))) {
    throw new Error(`the ${what} signature does not verify under the signing certificate`);
  }
  const t = now.getTime();
  if (t < s.statement.issueDate.getTime()) throw new Error(`the ${what} is not yet valid`);
  if (t > s.statement.nextUpdate.getTime()) throw new Error(`the ${what} is past its next update`);
}

function checkTcbInfo(info: TcbInfo): void {
  if (info.id !== TCB_INFO_ID) throw new Error(`tcbInfo id ${JSON.stringify(info.id)} is not ${JSON.stringify(TCB_INFO_ID)}`);
  if (info.version !== TCB_INFO_VERSION) throw new Error(`tcbInfo version ${info.version} is not ${TCB_INFO_VERSION}`);
  if (info.tcbLevels.length === 0) throw new Error("tcbInfo has no TCB levels");
}

function checkQeIdentity(qe: QeIdentity): void {
  if (qe.id !== QE_IDENTITY_ID) throw new Error(`enclaveIdentity id ${JSON.stringify(qe.id)} is not ${JSON.stringify(QE_IDENTITY_ID)}`);
  if (qe.version !== QE_IDENTITY_VERSION) throw new Error(`enclaveIdentity version ${qe.version} is not ${QE_IDENTITY_VERSION}`);
  if (qe.tcbLevels.length === 0) throw new Error("enclaveIdentity has no TCB levels");
}

/**
 * The QE report is signed by the PCK certificate and its report data binds
 * the attestation key (SHA-256 of the key and the QE authentication data,
 * zero-padded); the quote's header and body are signed by that key.
 */
async function verifySignatures(quote: ParsedQuote, leaf: Certificate): Promise<void> {
  if (!(await verifyP256(leaf.spki, "spki", quote.qeReport.raw, quote.qeReportSignature))) {
    throw new Error("the QE report signature does not verify under the PCK certificate");
  }
  const bound = await sha256(concat(quote.attestationKey, quote.qeAuthData));
  const expected = new Uint8Array(REPORT_DATA_SIZE);
  expected.set(bound);
  if (!bytesEqual(expected, quote.qeReport.reportData)) throw new Error("the QE report data does not bind the attestation key");
  const point = concat(new Uint8Array([0x04]), quote.attestationKey);
  if (!(await verifyP256(point, "raw", quote.signedBytes, quote.signature))) throw new Error("the quote signature does not verify under the attestation key");
}

/** ECDSA P-256 with SHA-256 over `data`, the signature as r then s; an unusable key or malformed signature does not verify. */
async function verifyP256(key: Uint8Array, format: "spki" | "raw", data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (signature.length !== 64) return false;
  try {
    const k = await crypto.subtle.importKey(format, key as Uint8Array<ArrayBuffer>, P256, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, signature as Uint8Array<ArrayBuffer>, data as Uint8Array<ArrayBuffer>);
  } catch {
    return false;
  }
}

/** The quote body against the TCB info: FMSPC and PCEID of the PCK certificate, the TDX module's signer and attributes, and the TCB status. */
function checkQuoteBody(quote: ParsedQuote, info: TcbInfo, pck: PckExtensions): void {
  const fmspc = toHex(pck.fmspc);
  if (fmspc !== info.fmspc) throw new Error(`PCK certificate FMSPC ${fmspc} is not the TCB info's ${JSON.stringify(info.fmspc)}`);
  const pceId = toHex(pck.pceId);
  if (pceId !== info.pceId) throw new Error(`PCK certificate PCEID ${pceId} is not the TCB info's ${JSON.stringify(info.pceId)}`);
  const body = quote.body;
  if (!bytesEqual(info.tdxModule.mrSigner, body.mrSignerSeam)) throw new Error("MRSIGNERSEAM is not the TCB info's TDX module signer");
  if (info.tdxModule.attributesMask.length !== body.seamAttributes.length) {
    throw new Error("the TCB info's TDX module attributes mask is not the size of SEAMATTRIBUTES");
  }
  if (!bytesEqual(info.tdxModule.attributes, mask(body.seamAttributes, info.tdxModule.attributesMask))) {
    throw new Error("SEAMATTRIBUTES under the TCB info's mask are not the TDX module's attributes");
  }
  checkTcbStatus(info, body, pck);
}

/** The QE report against the QE identity: MISCSELECT and attributes under their masks, MRSIGNER, ISV product id, and the QE's TCB status. */
function checkQeReport(quote: ParsedQuote, qe: QeIdentity): void {
  const report = quote.qeReport;
  if (qe.miscSelectMask.length !== 4) throw new Error("the QE identity's MISCSELECT mask is not 4 bytes");
  if (qe.miscSelect.length !== 4) throw new Error("the QE identity's MISCSELECT is not 4 bytes");
  const le = (b: Uint8Array): number => new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
  if (((report.miscSelect & le(qe.miscSelectMask)) >>> 0) !== le(qe.miscSelect)) throw new Error("QE MISCSELECT under the mask is not the QE identity's");
  if (qe.attributesMask.length !== report.attributes.length) throw new Error("the QE identity's attributes mask is not the size of the QE attributes");
  if (!bytesEqual(qe.attributes, mask(report.attributes, qe.attributesMask))) throw new Error("QE attributes under the mask are not the QE identity's");
  if (!bytesEqual(qe.mrSigner, report.mrSigner)) throw new Error("QE MRSIGNER is not the QE identity's");
  if (report.isvProdId !== qe.isvProdId) throw new Error(`QE ISV product id ${report.isvProdId} is not the QE identity's ${qe.isvProdId}`);
  checkQeTcbStatus(qe.tcbLevels, report);
}

function mask(value: Uint8Array, m: Uint8Array): Uint8Array {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) out[i] = value[i] & m[i];
  return out;
}

// ---------------------------------------------------------------- expectations

/** Expectations a policy fixes for a quote, fully resolved so validation compares and nothing else. */
export interface TdxExpectations {
  readonly qeVendorId: Uint8Array;
  readonly minimumTeeTcbSvn: Uint8Array;
  readonly mrSeam: Uint8Array;
  readonly tdAttributes: Uint8Array;
  readonly xfam: Uint8Array;
  readonly measurement: TdxMeasurement;
  readonly mrConfigId: Uint8Array;
  readonly mrOwner: Uint8Array;
  readonly mrOwnerConfig: Uint8Array;
  readonly reportData: Uint8Array;
  readonly minimumTcbEvaluationDataNumber: bigint;
}

/**
 * Translates a validated policy, the resolved measurement, the document's
 * REPORT_DATA and the expected MRCONFIGID into expectations. MROWNER and
 * MROWNERCONFIG are expected to be zero.
 */
export function assembleTdx(policy: TdxPolicy, _q: TdxQuote, m: TdxMeasurement, reportData: Uint8Array, mrConfigId: Uint8Array): TdxExpectations {
  validateTdxPolicy(policy);
  if (reportData.length !== REPORT_DATA_SIZE) throw new Error(`REPORT_DATA must be ${REPORT_DATA_SIZE} bytes`);
  if (mrConfigId.length !== MR_CONFIG_ID_SIZE) throw new Error(`MRCONFIGID must be ${MR_CONFIG_ID_SIZE} bytes`);
  return {
    qeVendorId: decodeHex("qe_vendor_id", policy.qeVendorId, 16),
    minimumTeeTcbSvn: decodeHex("minimum_tee_tcb_svn", policy.minimumTeeTcbSvn, 16),
    mrSeam: decodeHex("mr_seam", policy.mrSeam, 48),
    tdAttributes: decodeHex("td_attributes", policy.tdAttributes, 8),
    xfam: decodeHex("xfam", policy.xfam, 8),
    measurement: { platform: "tdx", mrtd: m.mrtd.slice(), rtmr0: m.rtmr0.slice(), rtmr1: m.rtmr1.slice(), rtmr2: m.rtmr2.slice(), rtmr3: m.rtmr3.slice() },
    mrConfigId: mrConfigId.slice(),
    mrOwner: new Uint8Array(48),
    mrOwnerConfig: new Uint8Array(48),
    reportData: reportData.slice(),
    minimumTcbEvaluationDataNumber: policy.minimumTcbEvaluationDataNumber!,
  };
}

/**
 * Validates the quote against the expectations: QE vendor id, MRSEAM, TD
 * attributes, XFAM, MRTD and all four RTMRs, MRCONFIGID, zero MROWNER and
 * MROWNERCONFIG and REPORT_DATA byte for byte; every TEE TCB SVN component
 * at least the minimum; XFAM and TD attributes within the fixed bit masks
 * every accepted TD must satisfy; and the TCB evaluation data number at
 * least the policy's floor.
 */
export function validateTdx(e: TdxExpectations, q: TdxQuote): void {
  const { header, body } = q.quote;
  const exact = (name: string, got: Uint8Array, want: Uint8Array): void => {
    if (!bytesEqual(got, want)) throw new Error(`quote field ${name} is ${toHex(got)}, expected ${toHex(want)}`);
  };
  exact("QE_VENDOR_ID", header.qeVendorId, e.qeVendorId);
  exact("MR_SEAM", body.mrSeam, e.mrSeam);
  exact("TD_ATTRIBUTES", body.tdAttributes, e.tdAttributes);
  exact("XFAM", body.xfam, e.xfam);
  exact("MR_TD", body.mrTd, e.measurement.mrtd);
  exact("MR_CONFIG_ID", body.mrConfigId, e.mrConfigId);
  exact("MR_OWNER", body.mrOwner, e.mrOwner);
  exact("MR_OWNER_CONFIG", body.mrOwnerConfig, e.mrOwnerConfig);
  const rtmrs = [e.measurement.rtmr0, e.measurement.rtmr1, e.measurement.rtmr2, e.measurement.rtmr3];
  rtmrs.forEach((want, i) => exact(`RTMR[${i}]`, body.rtmrs[i], want));
  exact("REPORT_DATA", body.reportData, e.reportData);
  for (let i = 0; i < e.minimumTeeTcbSvn.length; i++) {
    if (body.teeTcbSvn[i] < e.minimumTeeTcbSvn[i]) {
      throw new Error(`TEE TCB SVN ${toHex(body.teeTcbSvn)} is below the required minimum ${toHex(e.minimumTeeTcbSvn)}`);
    }
  }
  const xfam = littleEndian64(body.xfam);
  if ((xfam & XFAM_FIXED1) !== XFAM_FIXED1) throw new Error(`XFAM 0x${xfam.toString(16)} clears required bits 0x${XFAM_FIXED1.toString(16)}`);
  if ((xfam & ~XFAM_FIXED0) !== 0n) throw new Error(`XFAM 0x${xfam.toString(16)} sets bits outside 0x${XFAM_FIXED0.toString(16)}`);
  const attrs = littleEndian64(body.tdAttributes);
  if ((attrs & ~TD_ATTRIBUTES_FIXED0) !== 0n) {
    throw new Error(`TD attributes 0x${attrs.toString(16)} set bits outside 0x${TD_ATTRIBUTES_FIXED0.toString(16)}`);
  }
  if (q.tcbEvaluationDataNumber < e.minimumTcbEvaluationDataNumber) {
    throw new Error(`tcbEvaluationDataNumber ${q.tcbEvaluationDataNumber} is below the policy minimum ${e.minimumTcbEvaluationDataNumber}`);
  }
}

function littleEndian64(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return BigInt.asUintN(64, v);
}

export type { PcsCollateral };
