/**
 * Intel PCS collateral replayed from captured responses: lookup by canonical
 * URL, the TCB info and QE identity statements with their signatures and
 * issuer chains, the CRLs, and the TCB level evaluation the statements
 * define.
 *
 * A statement response is `{"<member>": {...}, "signature": "<hex>"}`; the
 * signature is ECDSA P-256 over the exact bytes of the member's value, so
 * those bytes are located in the response rather than re-serialized. Issuer
 * chains arrive URL-encoded in a response header, signing certificate first
 * and root second. Members this verifier does not read are allowed, as a
 * live verifier must accept newer statements.
 */
import type { PcsResponse } from "../../../document/collateral/tdx.js";
import { toHex } from "../../bytes.js";
import { arr, num, object, str, strArr, uint, int64 } from "../../json/decode.js";
import { JsonError, strictParse, type JsonObject, type JsonValue } from "../../json/index.js";
import { parseRfc3339 } from "../../rfc3339.js";
import { expectSequence, extension, isContext, parseCertificate, type Certificate, X509Error } from "../../x509/certificate.js";
import { children, decode, DerError, pemBlocks } from "../../x509/der.js";
import type { TdxQuoteBody, QeReport } from "./abi.js";
import type { PckExtensions } from "./pck.js";

const PCS_SGX_BASE = "https://api.trustedservices.intel.com/sgx/certification/v4";
const PCS_TDX_BASE = "https://api.trustedservices.intel.com/tdx/certification/v4";
const EVALUATION_NUMBER_QUERY = "tcbEvaluationDataNumber";

export const HEADER_PCK_CRL_ISSUER_CHAIN = "Sgx-Pck-Crl-Issuer-Chain";
export const HEADER_TCB_INFO_ISSUER_CHAIN = "Tcb-Info-Issuer-Chain";
export const HEADER_QE_IDENTITY_ISSUER_CHAIN = "Sgx-Enclave-Identity-Issuer-Chain";

export const TCB_INFO_ID = "TDX";
export const TCB_INFO_VERSION = 3;
export const QE_IDENTITY_ID = "TD_QE";
export const QE_IDENTITY_VERSION = 2;
export const TCB_STATUS_UP_TO_DATE = "UpToDate";
const TCB_STATUSES = new Set([
  TCB_STATUS_UP_TO_DATE,
  "SWHardeningNeeded",
  "ConfigurationNeeded",
  "ConfigurationAndSWHardeningNeeded",
  "OutOfDate",
  "OutOfDateConfigurationNeeded",
  "Revoked",
]);
const TDX_MODULE_ID_PREFIX = "TDX_";
const OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";

/** The PCS URL of the PCK CRL for an issuing CA ("platform" or "processor"). */
export function pckCrlUrl(ca: string): string {
  return `${PCS_SGX_BASE}/pckcrl?ca=${ca}&encoding=der`;
}

/** The PCS URL of the TDX TCB info for an FMSPC (lowercase hex). */
export function tcbInfoUrl(fmspc: string): string {
  return `${PCS_TDX_BASE}/tcb?fmspc=${fmspc}`;
}

/** The PCS URL of the TDX QE identity. */
export function qeIdentityUrl(): string {
  return `${PCS_TDX_BASE}/qe/identity`;
}

/** The captured responses indexed by URL with the tcbEvaluationDataNumber query dropped, lowercased. */
export interface PcsCollateral {
  get(url: string): PcsResponse | undefined;
}

/**
 * The canonical lookup form of a PCS URL: the tcbEvaluationDataNumber
 * query, which selects a collateral edition, is dropped so a capture made
 * at one edition answers the edition-less request; the remaining query is
 * sorted; the whole URL is lowercased.
 */
export function collateralKey(rawUrl: string): string {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new Error(`PCS URL ${JSON.stringify(rawUrl)} is not a URL`);
  }
  const q = new URLSearchParams(u.search);
  q.delete(EVALUATION_NUMBER_QUERY);
  q.sort();
  u.search = q.toString();
  return u.toString().toLowerCase();
}

/** Indexes captured responses; a URL captured twice keeps the later response. */
export function indexCollateral(responses: readonly PcsResponse[]): PcsCollateral {
  const m = new Map<string, PcsResponse>();
  for (const r of responses) m.set(collateralKey(r.url), r);
  return { get: (url) => m.get(collateralKey(url)) };
}

function fetchCaptured(c: PcsCollateral, url: string, what: string): PcsResponse {
  const r = c.get(url);
  if (r === undefined) throw new Error(`intel-pcs collateral has no captured response for the ${what} (${url})`);
  return r;
}

/**
 * The issuer chain a response header carries: exactly one value, URL-encoded
 * PEM text with exactly two certificates, the signing certificate then the
 * root. Header names match regardless of case.
 */
export function issuerChain(response: PcsResponse, name: string): { signing: Certificate; root: Certificate } {
  const wanted = name.toLowerCase();
  let values: readonly string[] | undefined;
  for (const [k, v] of response.headers ?? []) {
    if (k.toLowerCase() === wanted) {
      if (values !== undefined) throw new Error(`PCS response carries the ${name} header more than once`);
      values = v;
    }
  }
  if (values === undefined) throw new Error(`PCS response has no ${name} header`);
  if (values.length !== 1) throw new Error(`${name} header must carry one value, found ${values.length}`);
  if (values[0] === "") throw new Error(`${name} header is empty`);
  let pem: string;
  try {
    pem = decodeURIComponent(values[0].replace(/\+/g, " "));
  } catch {
    throw new Error(`${name} header is not URL-encoded`);
  }
  let blocks: Uint8Array[];
  try {
    blocks = pemBlocks(pem, "CERTIFICATE");
  } catch (err) {
    throw new Error(`${name} header: ${(err as Error).message}`);
  }
  if (blocks.length !== 2) throw new Error(`${name} header carries ${blocks.length} certificates, expected 2 (signing, root)`);
  try {
    return { signing: parseCertificate(blocks[0]), root: parseCertificate(blocks[1]) };
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`${name} header: ${err.message}`);
    throw err;
  }
}

/** The URIs named by a certificate's CRL distribution points extension, in order; none when the extension is absent. */
export function crlDistributionPointUris(cert: Certificate): string[] {
  const ext = extension(cert, OID_CRL_DISTRIBUTION_POINTS);
  if (ext === undefined) return [];
  const out: string[] = [];
  try {
    for (const point of expectSequence(decode(ext.value), "CRL distribution points")) {
      for (const field of expectSequence(point, "distribution point")) {
        // [0] EXPLICIT DistributionPointName; fullName is its [0] IMPLICIT GeneralNames.
        if (!isContext(field, 0) || !field.constructed) continue;
        for (const name of children(field)) {
          if (!isContext(name, 0) || !name.constructed) continue;
          for (const general of children(name)) {
            // uniformResourceIdentifier [6] IMPLICIT IA5String.
            if (isContext(general, 6) && !general.constructed) out.push(ia5(general.value));
          }
        }
      }
    }
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`CRL distribution points: ${err.message}`);
    throw err;
  }
  return out;
}

function ia5(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    if (b > 0x7f) throw new Error("URI is not IA5String");
    s += String.fromCharCode(b);
  }
  return s;
}

// ---------------------------------------------------------------- statements

export interface TcbComponent {
  readonly svn: number;
}

export interface TcbLevel {
  readonly sgxComponents: readonly TcbComponent[];
  readonly tdxComponents: readonly TcbComponent[];
  readonly pceSvn: number;
  readonly isvSvn: number;
  readonly status: string;
}

export interface TdxModuleIdentity {
  readonly id: string;
  readonly tcbLevels: readonly TcbLevel[];
}

export interface TcbInfo {
  readonly id: string;
  readonly version: number;
  readonly issueDate: Date;
  readonly nextUpdate: Date;
  readonly fmspc: string;
  readonly pceId: string;
  readonly tcbEvaluationDataNumber: bigint;
  readonly tdxModule: { readonly mrSigner: Uint8Array; readonly attributes: Uint8Array; readonly attributesMask: Uint8Array };
  readonly tdxModuleIdentities: readonly TdxModuleIdentity[];
  readonly tcbLevels: readonly TcbLevel[];
  /** The exact bytes of the tcbInfo value, which the signature covers. */
  readonly signed: Uint8Array;
  /** ECDSA P-256 signature, r then s. */
  readonly signature: Uint8Array;
}

export interface QeIdentity {
  readonly id: string;
  readonly version: number;
  readonly issueDate: Date;
  readonly nextUpdate: Date;
  readonly tcbEvaluationDataNumber: bigint;
  readonly miscSelect: Uint8Array;
  readonly miscSelectMask: Uint8Array;
  readonly attributes: Uint8Array;
  readonly attributesMask: Uint8Array;
  readonly mrSigner: Uint8Array;
  readonly isvProdId: number;
  readonly tcbLevels: readonly TcbLevel[];
  readonly signed: Uint8Array;
  readonly signature: Uint8Array;
}

/** A statement response with its issuer chain. */
export interface Statement<T> {
  readonly statement: T;
  readonly signing: Certificate;
  readonly root: Certificate;
}

/** Reads and decodes the captured TCB info for `fmspc` (lowercase hex). */
export function tcbInfo(c: PcsCollateral, fmspc: string): Statement<TcbInfo> {
  const response = fetchCaptured(c, tcbInfoUrl(fmspc), "TCB info");
  const chain = issuerChain(response, HEADER_TCB_INFO_ISSUER_CHAIN);
  return { statement: decodeTcbInfo(response.body), ...chain };
}

/** Reads and decodes the captured QE identity. */
export function qeIdentity(c: PcsCollateral): Statement<QeIdentity> {
  const response = fetchCaptured(c, qeIdentityUrl(), "QE identity");
  const chain = issuerChain(response, HEADER_QE_IDENTITY_ISSUER_CHAIN);
  return { statement: decodeQeIdentity(response.body), ...chain };
}

/** The captured PCK CRL body for the issuing CA, with its issuer chain. */
export function pckCrl(c: PcsCollateral, ca: string): { body: Uint8Array; signing: Certificate; root: Certificate } {
  const response = fetchCaptured(c, pckCrlUrl(ca), "PCK CRL");
  return { body: response.body, ...issuerChain(response, HEADER_PCK_CRL_ISSUER_CHAIN) };
}

/** The captured root CA CRL body: the first of `uris` with a captured response. */
export function rootCrl(c: PcsCollateral, uris: readonly string[]): Uint8Array {
  if (uris.length === 0) throw new Error("the issuer chain's root certificate names no CRL distribution point");
  for (const uri of uris) {
    const r = c.get(uri);
    if (r !== undefined) return r.body;
  }
  throw new Error(`intel-pcs collateral has no captured response for the root CA CRL (${uris.join(", ")})`);
}

function decodeStatement(body: Uint8Array, member: string): { value: JsonObject; signed: Uint8Array; signature: Uint8Array } {
  if (body.length === 0) throw new Error(`${member} response is empty`);
  let top: JsonValue;
  try {
    top = strictParse(body);
  } catch (err) {
    throw new Error(`${member} response: ${(err as Error).message}`);
  }
  const o = object(top, `${member} response`);
  const value = o.get(member);
  if (value === undefined) throw new Error(`${member} response has no ${JSON.stringify(member)} member`);
  const signature = hexBytes(o, "signature");
  if (signature.length !== 64) throw new Error(`${member} signature is ${signature.length} bytes, expected 64`);
  return { value: object(value, member), signed: memberValueBytes(body, member), signature };
}

function decodeTcbInfo(body: Uint8Array): TcbInfo {
  const { value: o, signed, signature } = decodeStatement(body, "tcbInfo");
  try {
    const module = object(o.get("tdxModule") ?? null, "tdxModule");
    return {
      id: str(o, "id"),
      version: small(o, "version", 8),
      issueDate: requiredTime(o, "issueDate", "tcbInfo"),
      nextUpdate: requiredTime(o, "nextUpdate", "tcbInfo"),
      fmspc: str(o, "fmspc"),
      pceId: str(o, "pceId"),
      tcbEvaluationDataNumber: requiredEvaluationNumber(o, "tcbInfo"),
      tdxModule: { mrSigner: hexBytes(module, "mrsigner"), attributes: hexBytes(module, "attributes"), attributesMask: hexBytes(module, "attributesMask") },
      tdxModuleIdentities: (arr(o, "tdxModuleIdentities") ?? []).map((v) => {
        const m = object(v, "tdxModuleIdentity");
        // The identity's own measurement and attributes are decoded for
        // shape but not compared; only its id and levels select a status.
        hexBytes(m, "mrsigner");
        hexBytes(m, "attributes");
        hexBytes(m, "attributesMask");
        return { id: str(m, "id"), tcbLevels: tcbLevels(m) };
      }),
      tcbLevels: tcbLevels(o),
      signed,
      signature,
    };
  } catch (err) {
    if (err instanceof JsonError) throw new Error(`tcbInfo: ${err.message}`);
    throw err;
  }
}

function decodeQeIdentity(body: Uint8Array): QeIdentity {
  const { value: o, signed, signature } = decodeStatement(body, "enclaveIdentity");
  try {
    return {
      id: str(o, "id"),
      version: small(o, "version", 8),
      issueDate: requiredTime(o, "issueDate", "enclaveIdentity"),
      nextUpdate: requiredTime(o, "nextUpdate", "enclaveIdentity"),
      tcbEvaluationDataNumber: requiredEvaluationNumber(o, "enclaveIdentity"),
      miscSelect: hexBytes(o, "miscselect"),
      miscSelectMask: hexBytes(o, "miscselectMask"),
      attributes: hexBytes(o, "attributes"),
      attributesMask: hexBytes(o, "attributesMask"),
      mrSigner: hexBytes(o, "mrsigner"),
      isvProdId: small(o, "isvprodid", 16),
      tcbLevels: tcbLevels(o),
      signed,
      signature,
    };
  } catch (err) {
    if (err instanceof JsonError) throw new Error(`enclaveIdentity: ${err.message}`);
    throw err;
  }
}

function tcbLevels(o: JsonObject): TcbLevel[] {
  return (arr(o, "tcbLevels") ?? []).map((v) => {
    const level = object(v, "tcbLevel");
    const tcb = object(level.get("tcb") ?? null, "tcb");
    str(level, "tcbDate");
    strArr(level, "advisoryIDs");
    const status = level.get("tcbStatus");
    if (status === undefined) throw new Error("tcbLevel has no tcbStatus");
    if (typeof status !== "string" || !TCB_STATUSES.has(status)) throw new Error(`unexpected tcb status ${JSON.stringify(status)}`);
    return {
      sgxComponents: components(tcb, "sgxtcbcomponents"),
      tdxComponents: components(tcb, "tdxtcbcomponents"),
      pceSvn: small(tcb, "pcesvn", 16),
      isvSvn: small(tcb, "isvsvn", 32),
      status,
    };
  });
}

function components(tcb: JsonObject, key: string): TcbComponent[] {
  return (arr(tcb, key) ?? []).map((v) => {
    const c = object(v, key);
    str(c, "category");
    str(c, "type");
    return { svn: small(c, "svn", 8) };
  });
}

/** An unsigned integer member of `bits` width as a number; absent is 0. */
function small(o: JsonObject, key: string, bits: 8 | 32 | 16): number {
  const v = bits === 16 ? uint(o, key, 32) : uint(o, key, bits);
  if (v === undefined) return 0;
  if (bits === 16 && v > 0xffffn) throw new Error(`${key} ${v} overflows uint16`);
  return Number(v);
}

/** A hex string member as bytes; absent is empty, null rejects. */
function hexBytes(o: JsonObject, key: string): Uint8Array {
  const v = o.get(key);
  if (v === undefined) return new Uint8Array();
  if (typeof v !== "string") throw new Error(`${key} must be a hex string`);
  if (v.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(v)) throw new Error(`${key} is not hex`);
  const out = new Uint8Array(v.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(v.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function requiredTime(o: JsonObject, key: string, what: string): Date {
  const v = o.get(key);
  if (v === undefined || v === null) throw new Error(`${what} states no ${key}`);
  if (typeof v !== "string") throw new Error(`${what} ${key} must be a string`);
  return parseRfc3339(v, `${what} ${key}`);
}

function requiredEvaluationNumber(o: JsonObject, what: string): bigint {
  if (num(o, EVALUATION_NUMBER_QUERY) === undefined) throw new Error(`${what} states no ${EVALUATION_NUMBER_QUERY}`);
  return int64(o, EVALUATION_NUMBER_QUERY)!;
}

/**
 * The bytes of the top-level member `name`'s value within `body`, which has
 * already parsed as a JSON object: the text is walked member by member,
 * skipping each value by its syntax, until the name matches.
 */
export function memberValueBytes(body: Uint8Array, name: string): Uint8Array {
  const text = new TextDecoder().decode(body);
  let i = skipSpace(text, 0);
  if (text[i] !== "{") throw new Error("statement is not an object");
  i = skipSpace(text, i + 1);
  while (text[i] !== "}") {
    const keyEnd = skipString(text, i);
    const key = JSON.parse(text.slice(i, keyEnd)) as string;
    i = skipSpace(text, keyEnd);
    i = skipSpace(text, i + 1); // ':'
    const valueEnd = skipValue(text, i);
    if (key === name) return new TextEncoder().encode(text.slice(i, valueEnd));
    i = skipSpace(text, valueEnd);
    if (text[i] === ",") i = skipSpace(text, i + 1);
  }
  throw new Error(`statement has no ${JSON.stringify(name)} member`);
}

function skipSpace(text: string, i: number): number {
  while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  return i;
}

function skipString(text: string, i: number): number {
  i++; // opening quote
  while (i < text.length) {
    const c = text[i];
    if (c === "\\") i += 2;
    else if (c === '"') return i + 1;
    else i++;
  }
  throw new Error("statement string is unterminated");
}

function skipValue(text: string, i: number): number {
  const c = text[i];
  if (c === '"') return skipString(text, i);
  if (c === "{" || c === "[") {
    const close = c === "{" ? "}" : "]";
    i = skipSpace(text, i + 1);
    while (text[i] !== close) {
      if (c === "{") {
        i = skipSpace(text, skipString(text, i));
        i = skipSpace(text, i + 1); // ':'
      }
      i = skipSpace(text, skipValue(text, i));
      if (text[i] === ",") i = skipSpace(text, i + 1);
    }
    return i + 1;
  }
  while (i < text.length && !",}] \t\n\r".includes(text[i])) i++;
  return i;
}

// ---------------------------------------------------------------- evaluation

/** True when every byte of `svn` is at least the matching component's SVN; lengths must agree. */
function svnAtLeast(svn: Uint8Array, comps: readonly TcbComponent[], from: number): boolean {
  if (svn.length !== comps.length) return false;
  for (let i = from; i < svn.length; i++) if (svn[i] < comps[i].svn) return false;
  return true;
}

/**
 * The first TCB level the platform satisfies: every CPU SVN component, the
 * PCE SVN, and every TEE TCB SVN component at least the level's. When the
 * TEE TCB SVN names a versioned TDX module (byte 1 non-zero) its first two
 * bytes identify the module instead and are skipped.
 */
export function matchingTcbLevel(levels: readonly TcbLevel[], body: TdxQuoteBody, pck: PckExtensions): TcbLevel {
  const from = body.teeTcbSvn[1] > 0 ? 2 : 0;
  for (const level of levels) {
    if (svnAtLeast(pck.cpuSvnComponents, level.sgxComponents, 0) && pck.pceSvn >= level.pceSvn && svnAtLeast(body.teeTcbSvn, level.tdxComponents, from)) {
      return level;
    }
  }
  throw new Error("no TCB level in the TCB info matches the platform");
}

/** The TDX module identity level for a versioned module: id "TDX_<version>", the first level whose ISV SVN the module's meets. */
export function matchingTdxModuleLevel(identities: readonly TdxModuleIdentity[], teeTcbSvn: Uint8Array): TcbLevel {
  const id = TDX_MODULE_ID_PREFIX + toHex(teeTcbSvn.subarray(1, 2));
  const isvSvn = teeTcbSvn[0];
  for (const identity of identities) {
    if (identity.id !== id) continue;
    for (const level of identity.tcbLevels) if (isvSvn >= level.isvSvn) return level;
    throw new Error(`no TDX module identity TCB level matches the module's ISV SVN ${isvSvn}`);
  }
  throw new Error(`the TCB info names no TDX module identity ${id}`);
}

/**
 * The TCB status of the platform: the matching level, and for a versioned
 * TDX module the module's level too, must both be up to date.
 */
export function checkTcbStatus(info: TcbInfo, body: TdxQuoteBody, pck: PckExtensions): void {
  const level = matchingTcbLevel(info.tcbLevels, body, pck);
  if (body.teeTcbSvn[1] > 0) {
    const module = matchingTdxModuleLevel(info.tdxModuleIdentities, body.teeTcbSvn);
    if (module.status !== TCB_STATUS_UP_TO_DATE) throw new Error(`TDX module TCB status is ${module.status}, not ${TCB_STATUS_UP_TO_DATE}`);
  }
  if (level.status !== TCB_STATUS_UP_TO_DATE) throw new Error(`TCB status is ${level.status}, not ${TCB_STATUS_UP_TO_DATE}`);
}

/** The QE's TCB status: the first level whose ISV SVN the QE meets must be up to date. */
export function checkQeTcbStatus(levels: readonly TcbLevel[], report: QeReport): void {
  for (const level of levels) {
    if (level.isvSvn <= report.isvSvn) {
      if (level.status !== TCB_STATUS_UP_TO_DATE) throw new Error(`QE TCB status is ${level.status}, not ${TCB_STATUS_UP_TO_DATE}`);
      return;
    }
  }
  throw new Error("no QE identity TCB level matches the QE's ISV SVN");
}
