// DCAP TDX quote-v4 verification, a 1:1 port of go-tdx-guest/verify for the
// exact configuration tinfoil-go uses: Getter (collateral replay),
// TrustedRoots (single pinned Intel SGX root), GetCollateral=true,
// CheckRevocations=true, Now pinned. All errors are plain Errors; the
// authenticate wrapper assigns QUOTE_REJECTED.

import { bytesEqual, decodeHex, encodeHex, sha256 } from "../bytes.js";
import {
  basicConstraints,
  bytesToLatin1,
  crlDistributionPointURIs,
  derBytesEqual,
  ecdsaP256PublicKey,
  keyUsage,
  parseCertificate,
  parseCRL,
  pemDecode,
  verifyDERSignature,
  verifyRawSignature,
  type Certificate,
  type CRL,
} from "./der.js";
import {
  parseQeIdentity,
  parseTdxTcbInfo,
  pckCertificateExtensions,
  pckCrlURL,
  qeIdentityURL,
  rawTopLevelMember,
  tcbInfoURL,
  TcbComponentStatusUpToDate,
  type EnclaveIdentity,
  type PckExtensions,
  type QeIdentity,
  type TcbComponent,
  type TcbInfo,
  type TcbLevel,
  type TdxTcbInfo,
} from "./pcs.js";
import type { EnclaveReport, QuoteV4, TDQuoteBody } from "./quote.js";

const tcbInfoVersion = 3;
const qeIdentityVersion = 2;

const rootCertPhrase = "Intel SGX Root CA";
const intermediateCertPhrase = "Intel SGX PCK Platform CA";
const pckCertPhrase = "Intel SGX PCK Certificate";
const processorIssuer = "Intel SGX PCK Processor CA";
const processorIssuerID = "processor";
const platformIssuer = "Intel SGX PCK Platform CA";
const platformIssuerID = "platform";
const sgxPckCrlIssuerChainPhrase = "Sgx-Pck-Crl-Issuer-Chain";
const sgxQeIdentityIssuerChainPhrase = "Sgx-Enclave-Identity-Issuer-Chain";
const tcbInfoIssuerChainPhrase = "Tcb-Info-Issuer-Chain";
const tcbSigningPhrase = "Intel SGX TCB Signing";
const tcbInfoID = "TDX";
const qeIdentityID = "TD_QE";
const tcbInfoTdxModuleIDPrefix = "TDX_";

const oidECDSAWithSHA256 = "1.2.840.10045.4.3.2";
const oidECPublicKey = "1.2.840.10045.2.1";
const oidP256 = "1.2.840.10045.3.1.7";

// HTTPSGetter mirrors trust.HTTPSGetter: URL in, response headers + body out.
export interface HTTPSGetter {
  get(url: string): { headers: Map<string, string[]>; body: Uint8Array };
}

export interface VerifyOptions {
  getter: HTTPSGetter;
  trustedRoot: Certificate; // single pinned Intel SGX root
  now: Date;
}

export interface PCKCertificateChain {
  pckCertificate: Certificate;
  rootCertificate: Certificate;
  intermediateCertificate: Certificate;
}

interface Collateral {
  pckCrlIssuerIntermediateCertificate?: Certificate;
  pckCrlIssuerRootCertificate?: Certificate;
  pckCrl?: CRL;
  tcbInfoIssuerIntermediateCertificate?: Certificate;
  tcbInfoIssuerRootCertificate?: Certificate;
  tdxTcbInfo?: TdxTcbInfo;
  tcbInfoBody?: Uint8Array;
  qeIdentityIssuerIntermediateCertificate?: Certificate;
  qeIdentityIssuerRootCertificate?: Certificate;
  qeIdentity?: QeIdentity;
  enclaveIdentityBody?: Uint8Array;
  rootCaCrl?: CRL;
}

function applyMask(a: Uint8Array, b: Uint8Array): Uint8Array {
  const data = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) data[i] = a[i] & b[i];
  return data;
}

function extractCaFromPckCert(pckCert: Certificate): string {
  const pckIssuer = pckCert.issuerCN;
  if (pckIssuer === platformIssuer) return platformIssuerID;
  if (pckIssuer === processorIssuer) return processorIssuerID;
  throw new Error("could not find CA from PCK certificate");
}

// extractChainFromQuoteV4 splits the concatenated PEM PCK chain (leaf ||
// intermediate || root, optionally null-terminated).
export function extractChainFromQuoteV4(quote: QuoteV4): PCKCertificateChain {
  const chainBytes = quote.signedData.certificationData.qeReportCertificationData.pckCertificateChainData.pckCertChain;
  if (chainBytes.length === 0) {
    throw new Error("PCK certificate chain is empty");
  }
  const invalid = () =>
    new Error(
      "incomplete PCK Certificate chain found, should contain 3 concatenated PEM-formatted 'CERTIFICATE'-type block (PCK Leaf Cert||Intermediate CA Cert||Root CA Cert)",
    );
  const text = bytesToLatin1(chainBytes);
  const pck = pemDecode(text);
  if (pck === undefined || pck.rest.length === 0 || pck.type !== "CERTIFICATE") throw invalid();
  const pckCert = parseCertificate(pck.der);

  const intermediate = pemDecode(pck.rest);
  if (intermediate === undefined || intermediate.rest.length === 0 || intermediate.type !== "CERTIFICATE") throw invalid();
  const intermediateCert = parseCertificate(intermediate.der);

  const root = pemDecode(intermediate.rest);
  if (root === undefined || root.type !== "CERTIFICATE") throw invalid();
  // The final byte of the certificate chain can be a null byte.
  if (root.rest.length !== 0 && root.rest !== "\x00") {
    throw new Error(`unexpected trailing bytes were found in PCK Certificate Chain: ${root.rest.length} byte(s)`);
  }
  const rootCert = parseCertificate(root.der);

  return { pckCertificate: pckCert, rootCertificate: rootCert, intermediateCertificate: intermediateCert };
}

function validateX509Cert(cert: Certificate): void {
  if (cert.version !== 3) {
    throw new Error(`certificate's version found ${cert.version}. Expected 3`);
  }
  if (cert.signatureAlgorithmOID !== oidECDSAWithSHA256) {
    throw new Error("certificate's signature algorithm is not ECDSA-SHA256");
  }
  if (cert.spkiAlgorithmOID !== oidECPublicKey) {
    throw new Error("certificate's public Key algorithm is not ECDSA");
  }
  if (cert.spkiCurveOID !== oidP256) {
    throw new Error('certificate\'s public key curve is not "P-256"');
  }
}

// checkSignatureFromCert mirrors x509.Certificate.CheckSignatureFrom's
// parent-constraint and signature checks.
async function checkSignatureFromCert(cert: Certificate, parent: Certificate, forCRL: boolean, tbs: Uint8Array, signature: Uint8Array): Promise<void> {
  const bc = basicConstraints(parent);
  if ((parent.version === 3 && !bc.present) || (bc.present && !bc.ca)) {
    throw new Error("x509: invalid signature: parent certificate cannot sign this kind of certificate");
  }
  const ku = keyUsage(parent);
  if (ku.present && !(forCRL ? ku.crlSign : ku.certSign)) {
    throw new Error("x509: invalid signature: parent certificate cannot sign this kind of certificate");
  }
  if (!(await verifyDERSignature(tbs, signature, parent))) {
    throw new Error("crypto/ecdsa: verification error");
  }
  void cert;
}

async function validateCertificate(cert: Certificate, parent: Certificate, phrase: string): Promise<void> {
  validateX509Cert(cert);
  if (cert.subjectCN !== phrase) {
    throw new Error(`${JSON.stringify(cert.subjectCN)} is not expected in certificate's subject name. Expected ${JSON.stringify(phrase)}`);
  }
  if (!derBytesEqual(cert.issuerDER, parent.subjectDER)) {
    throw new Error("certificate's issuer name does not match with parent certificate's subject name");
  }
  try {
    await checkSignatureFromCert(cert, parent, false, cert.tbs, cert.signature);
  } catch (err) {
    throw new Error(`certificate signature verification using parent certificate failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function validateCRL(crl: CRL | undefined, trustedCertificate: Certificate): Promise<void> {
  if (crl === undefined) throw new Error("CRL is empty");
  if (!derBytesEqual(crl.issuerDER, trustedCertificate.subjectDER)) {
    throw new Error("CRL issuer's name does not match with expected name");
  }
  const bc = basicConstraints(trustedCertificate);
  if ((trustedCertificate.version === 3 && !bc.present) || (bc.present && !bc.ca)) {
    throw new Error("CRL signature verification failed using trusted certificate: constraint violation");
  }
  const ku = keyUsage(trustedCertificate);
  if (ku.present && !ku.crlSign) {
    throw new Error("CRL signature verification failed using trusted certificate: constraint violation");
  }
  if (!(await verifyDERSignature(crl.tbs, crl.signature, trustedCertificate))) {
    throw new Error("CRL signature verification failed using trusted certificate");
  }
}

function checkValidity(cert: Certificate, now: Date, what: string): void {
  if (now.getTime() < cert.notBefore.getTime() || now.getTime() > cert.notAfter.getTime()) {
    throw new Error(`x509: ${what} has expired or is not yet valid`);
  }
}

// verifyChainToTrustedRoot mirrors x509.Certificate.Verify for the pools this
// configuration builds: the quote's intermediate (or none) and the single
// pinned root. Every candidate chain link matches by raw subject bytes.
async function verifyChainToTrustedRoot(leaf: Certificate, intermediate: Certificate | undefined, trustedRoot: Certificate, now: Date): Promise<void> {
  checkValidity(leaf, now, "leaf certificate");
  const tryParent = async (cert: Certificate, parent: Certificate, what: string): Promise<void> => {
    if (!derBytesEqual(cert.issuerDER, parent.subjectDER)) {
      throw new Error("x509: certificate signed by unknown authority");
    }
    checkValidity(parent, now, what);
    const bc = basicConstraints(parent);
    if (!bc.present || !bc.ca) {
      throw new Error("x509: certificate is not authorized to sign other certificates");
    }
    await checkSignatureFromCert(cert, parent, false, cert.tbs, cert.signature);
  };
  // Chain 1: leaf directly under the trusted root.
  if (derBytesEqual(leaf.issuerDER, trustedRoot.subjectDER)) {
    try {
      await tryParent(leaf, trustedRoot, "root certificate");
      return;
    } catch {
      // fall through to the intermediate chain
    }
  }
  if (intermediate === undefined) {
    throw new Error("x509: certificate signed by unknown authority");
  }
  await tryParent(leaf, intermediate, "intermediate certificate");
  await tryParent(intermediate, trustedRoot, "root certificate");
}

// Collateral acquisition (obtainCollateral and friends).

function headerToIssuerChain(headers: Map<string, string[]>, phrase: string): { intermediate: Certificate; root: Certificate } {
  const issuerChain = headers.get(phrase);
  if (issuerChain === undefined) {
    throw new Error(`${JSON.stringify(phrase)} is empty`);
  }
  if (issuerChain.length !== 1) {
    throw new Error(`issuer chain is expected to be of size 1, found ${issuerChain.length}`);
  }
  if (issuerChain[0] === "") {
    throw new Error(`issuer chain certificates missing in ${JSON.stringify(phrase)}`);
  }
  let certChain: string;
  try {
    // Go url.QueryUnescape: '+' is a space, %XX decoded.
    certChain = decodeURIComponent(issuerChain[0].replace(/\+/g, " "));
  } catch {
    throw new Error(`unable to decode issuer chain in ${JSON.stringify(phrase)}`);
  }
  const intermediate = pemDecode(certChain);
  if (intermediate === undefined || intermediate.rest.length === 0) {
    throw new Error(`could not parse PEM formatted signing certificate in ${JSON.stringify(phrase)}`);
  }
  if (intermediate.type !== "CERTIFICATE") {
    throw new Error(`the ${JSON.stringify(phrase)} PEM block type is ${JSON.stringify(intermediate.type)}. Expect "CERTIFICATE"`);
  }
  const root = pemDecode(intermediate.rest);
  if (root === undefined || root.rest.length !== 0) {
    throw new Error(`could not parse PEM formatted root certificate in ${JSON.stringify(phrase)}`);
  }
  if (root.type !== "CERTIFICATE") {
    throw new Error(`the ${JSON.stringify(phrase)} PEM block type is ${JSON.stringify(root.type)}. Expect "CERTIFICATE"`);
  }
  return { intermediate: parseCertificate(intermediate.der), root: parseCertificate(root.der) };
}

function bodyToCrl(body: Uint8Array): CRL {
  try {
    return parseCRL(body);
  } catch (err) {
    throw new Error(`unable to parse DER bytes of CRL: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function getPckCrl(ca: string, getter: HTTPSGetter, collateral: Collateral): void {
  const { headers, body } = getter.get(pckCrlURL(ca));
  const { intermediate, root } = headerToIssuerChain(headers, sgxPckCrlIssuerChainPhrase);
  collateral.pckCrlIssuerIntermediateCertificate = intermediate;
  collateral.pckCrlIssuerRootCertificate = root;
  collateral.pckCrl = bodyToCrl(body);
}

function getTcbInfo(fmspc: string, getter: HTTPSGetter, collateral: Collateral): void {
  const { headers, body } = getter.get(tcbInfoURL(fmspc));
  const { intermediate, root } = headerToIssuerChain(headers, tcbInfoIssuerChainPhrase);
  collateral.tcbInfoIssuerIntermediateCertificate = intermediate;
  collateral.tcbInfoIssuerRootCertificate = root;
  collateral.tdxTcbInfo = parseTdxTcbInfo(body);
  if (body.length === 0) throw new Error('"tcbInfo" is empty');
  const raw = rawTopLevelMember(body, "tcbInfo");
  if (raw === undefined) throw new Error('"tcbInfo" field is missing in the response received');
  collateral.tcbInfoBody = raw;
}

function getQeIdentity(getter: HTTPSGetter, collateral: Collateral): void {
  const { headers, body } = getter.get(qeIdentityURL());
  const { intermediate, root } = headerToIssuerChain(headers, sgxQeIdentityIssuerChainPhrase);
  collateral.qeIdentityIssuerIntermediateCertificate = intermediate;
  collateral.qeIdentityIssuerRootCertificate = root;
  collateral.qeIdentity = parseQeIdentity(body);
  if (body.length === 0) throw new Error('"enclaveIdentity" is empty');
  const raw = rawTopLevelMember(body, "enclaveIdentity");
  if (raw === undefined) throw new Error('"enclaveIdentity" field is missing in the response received');
  collateral.enclaveIdentityBody = raw;
}

function getRootCrl(getter: HTTPSGetter, collateral: Collateral): void {
  // The QE identity issuer chain's root certificate carries the Root CA CRL URL.
  const rootCrlURLs = crlDistributionPointURIs(collateral.qeIdentityIssuerRootCertificate!);
  if (rootCrlURLs.length === 0) {
    throw new Error("empty url found in QeIdentity issuer's chain which is required to receive ROOT CA CRL");
  }
  const errs: string[] = [];
  for (const url of rootCrlURLs) {
    try {
      const { body } = getter.get(url);
      collateral.rootCaCrl = bodyToCrl(body);
      return;
    } catch (err) {
      errs.push(err instanceof Error ? err.message : String(err));
    }
  }
  throw new Error(`${errs.join("; ")}; could not fetch root CRL`);
}

function obtainCollateral(fmspc: string, ca: string, getter: HTTPSGetter): Collateral {
  const collateral: Collateral = {};
  try {
    getTcbInfo(fmspc, getter, collateral);
  } catch (err) {
    throw new Error(`unable to receive tcbInfo: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    getQeIdentity(getter, collateral);
  } catch (err) {
    throw new Error(`unable to receive QeIdentity: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    getPckCrl(ca, getter, collateral);
  } catch (err) {
    throw new Error(`unable to receive PCK CRL: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    getRootCrl(getter, collateral);
  } catch (err) {
    throw new Error(`unable to receive Root CA CRL: ${err instanceof Error ? err.message : String(err)}`);
  }
  return collateral;
}

// Collateral presence and expiration (verifyCollateral).

function checkCollateralExpiration(collateral: Collateral, now: Date): void {
  const tcbInfo = collateral.tdxTcbInfo!.tcbInfo;
  const qeIdentity = collateral.qeIdentity!.enclaveIdentity;
  const t = now.getTime();
  if (t > tcbInfo.nextUpdate.getTime()) throw new Error("tcbInfo has expired");
  if (t > qeIdentity.nextUpdate.getTime()) throw new Error("QeIdentity has expired");
  if (t > collateral.tcbInfoIssuerIntermediateCertificate!.notAfter.getTime()) {
    throw new Error("tcbInfo signing certificate has expired");
  }
  if (t > collateral.tcbInfoIssuerRootCertificate!.notAfter.getTime()) {
    throw new Error("tcbInfo root certificate has expired");
  }
  if (t > collateral.qeIdentityIssuerRootCertificate!.notAfter.getTime()) {
    throw new Error("QeIdentity root certificate has expired");
  }
  if (t > collateral.qeIdentityIssuerIntermediateCertificate!.notAfter.getTime()) {
    throw new Error("QeIdentity signing certificate has expired");
  }
  if (t > collateral.rootCaCrl!.nextUpdate.getTime()) throw new Error("root CA CRL has expired");
  if (t > collateral.pckCrl!.nextUpdate.getTime()) throw new Error("PCK CRL has expired");
  if (t > collateral.pckCrlIssuerIntermediateCertificate!.notAfter.getTime()) {
    throw new Error("PCK CRL signing certificate has expired");
  }
  if (t > collateral.pckCrlIssuerRootCertificate!.notAfter.getTime()) {
    throw new Error("PCK CRL root certificate has expired");
  }
}

function verifyCollateral(collateral: Collateral, now: Date): void {
  if (collateral.tcbInfoBody === undefined) throw new Error("missing tcbInfo body in the collaterals obtained");
  if (collateral.enclaveIdentityBody === undefined) throw new Error("missing enclaveIdentity body in the collaterals obtained");
  if (collateral.tdxTcbInfo === undefined) throw new Error("tcbInfo is empty in collaterals");
  if (collateral.qeIdentity === undefined) throw new Error("QeIdentity is empty in collaterals");
  if (collateral.tcbInfoIssuerIntermediateCertificate === undefined) {
    throw new Error("missing signing certificate in the issuer chain of tcbInfo");
  }
  if (collateral.tcbInfoIssuerRootCertificate === undefined) {
    throw new Error("missing root certificate in the issuer chain of tcbInfo");
  }
  if (collateral.qeIdentityIssuerIntermediateCertificate === undefined) {
    throw new Error("missing signing certificate in the issuer chain of QeIdentity");
  }
  if (collateral.qeIdentityIssuerRootCertificate === undefined) {
    throw new Error("missing root certificate in the issuer chain of QeIdentity");
  }
  if (collateral.pckCrl === undefined) throw new Error("missing PCK CRL in the collaterals obtained");
  if (collateral.rootCaCrl === undefined) throw new Error("missing ROOT CA CRL in the collaterals obtained");
  if (collateral.pckCrlIssuerIntermediateCertificate === undefined) {
    throw new Error("missing signing certificate in the issuer chain of PCK CRL");
  }
  if (collateral.pckCrlIssuerRootCertificate === undefined) {
    throw new Error("missing root certificate in the issuer chain of PCK CRL");
  }
  checkCollateralExpiration(collateral, now);
}

// PCK certificate chain verification (verifyPCKCertificationChain).

function checkCertificateExpiration(chain: PCKCertificateChain, now: Date): void {
  const t = now.getTime();
  if (t > chain.rootCertificate.notAfter.getTime()) {
    throw new Error("root CA certificate in PCK certificate chain has expired");
  }
  if (t > chain.intermediateCertificate.notAfter.getTime()) {
    throw new Error("intermediate CA certificate in PCK certificate chain has expired");
  }
  if (t > chain.pckCertificate.notAfter.getTime()) {
    throw new Error("PCK leaf certificate in PCK certificate chain has expired");
  }
}

async function verifyPCKCertificationChain(chain: PCKCertificateChain, collateral: Collateral, opts: VerifyOptions): Promise<void> {
  const { rootCertificate: rootCert, intermediateCertificate: intermediateCert, pckCertificate: pckCert } = chain;

  // The root certificate must be self-signed.
  try {
    await validateCertificate(rootCert, rootCert, rootCertPhrase);
  } catch (err) {
    throw new Error(`unable to validate root cert: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    await validateCertificate(intermediateCert, rootCert, intermediateCertPhrase);
  } catch (err) {
    throw new Error(`unable to validate Intermediate CA certificate: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    await validateCertificate(pckCert, intermediateCert, pckCertPhrase);
  } catch (err) {
    throw new Error(`unable to validate PCK leaf certificate: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    await verifyChainToTrustedRoot(pckCert, intermediateCert, opts.trustedRoot, opts.now);
  } catch (err) {
    throw new Error(`error verifying PCK Certificate: ${err instanceof Error ? err.message : String(err)}`);
  }

  try {
    await validateCRL(collateral.rootCaCrl, rootCert);
  } catch (err) {
    throw new Error(
      `root CA CRL verification failed using root certificate in PCK Certificate chain: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  try {
    await validateCRL(collateral.pckCrl, intermediateCert);
  } catch (err) {
    throw new Error(
      `PCK CRL verification failed using intermediate certificate in PCK Certificate chain: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!derBytesEqual(collateral.pckCrl!.issuerDER, pckCert.issuerDER)) {
    throw new Error("issuer's name in PCK CRL does not match with PCK Leaf Certificate's issuer name");
  }
  for (const bad of collateral.rootCaCrl!.revokedSerialsHex) {
    if (bad === intermediateCert.serialHex) {
      throw new Error("intermediate certificate in PCK certificate chain was revoked");
    }
  }
  for (const bad of collateral.pckCrl!.revokedSerialsHex) {
    if (bad === pckCert.serialHex) {
      throw new Error("PCK Leaf certificate in PCK certificate chain was revoked");
    }
  }

  checkCertificateExpiration(chain, opts.now);
}

// Signed PCS response verification (verifyResponse / verifyTCBinfo /
// verifyQeIdentity).

async function verifyResponse(
  signingPhrase: string,
  rootCertificate: Certificate,
  signingCertificate: Certificate,
  rawBody: Uint8Array,
  rawSignature: string,
  crl: CRL | undefined,
  opts: VerifyOptions,
): Promise<void> {
  try {
    await validateCertificate(rootCertificate, rootCertificate, rootCertPhrase);
  } catch (err) {
    throw new Error(`unable to validate root certificate in the issuer chain: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    await validateCertificate(signingCertificate, rootCertificate, signingPhrase);
  } catch (err) {
    throw new Error(`unable to validate signing certificate in the issuer chain: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    await verifyChainToTrustedRoot(signingCertificate, undefined, opts.trustedRoot, opts.now);
  } catch (err) {
    throw new Error(`unable to verify signing certificate: ${err instanceof Error ? err.message : String(err)}`);
  }

  let signature: Uint8Array;
  try {
    signature = decodeHex(rawSignature);
  } catch (err) {
    throw new Error(`unable to decode signature string in the response: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (signature.length !== 0x40) {
    throw new Error(`unable to convert signature to DER format: signature size is ${signature.length} bytes. Expected 64 bytes`);
  }
  if (!(await verifyRawSignature(rawBody, signature, signingCertificate.spkiDER))) {
    throw new Error("could not verify response body using the signing certificate");
  }

  try {
    await validateCRL(crl, rootCertificate);
  } catch (err) {
    throw new Error(
      `root CA CRL verification failed using root certificate in the issuer's chain: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  for (const bad of crl!.revokedSerialsHex) {
    if (bad === signingCertificate.serialHex) {
      throw new Error("signing certificate was revoked");
    }
  }
}

async function verifyTCBinfo(collateral: Collateral, opts: VerifyOptions): Promise<void> {
  const tcbInfo = collateral.tdxTcbInfo!.tcbInfo;
  if (tcbInfo.id !== tcbInfoID) {
    throw new Error(`tcbInfo ID ${JSON.stringify(tcbInfo.id)} does not match with expected ID ${JSON.stringify(tcbInfoID)}`);
  }
  if (tcbInfo.version !== tcbInfoVersion) {
    throw new Error(`tcbInfo version ${tcbInfo.version} does not match with expected version ${tcbInfoVersion}`);
  }
  if (tcbInfo.tcbLevels.length === 0) {
    throw new Error("tcbInfo contains empty TcbLevels");
  }
  try {
    await verifyResponse(
      tcbSigningPhrase,
      collateral.tcbInfoIssuerRootCertificate!,
      collateral.tcbInfoIssuerIntermediateCertificate!,
      collateral.tcbInfoBody!,
      collateral.tdxTcbInfo!.signature,
      collateral.rootCaCrl,
      opts,
    );
  } catch (err) {
    throw new Error(`tcbInfo response verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function verifyQeIdentity(collateral: Collateral, opts: VerifyOptions): Promise<void> {
  const qeIdentity = collateral.qeIdentity!.enclaveIdentity;
  if (qeIdentity.id !== qeIdentityID) {
    throw new Error(`QeIdentity ID ${JSON.stringify(qeIdentity.id)} does not match with expected ID ${JSON.stringify(qeIdentityID)}`);
  }
  if (qeIdentity.version !== qeIdentityVersion) {
    throw new Error(`QeIdentity version ${qeIdentity.version} does not match with expected version ${qeIdentityVersion}`);
  }
  if (qeIdentity.tcbLevels.length === 0) {
    throw new Error("QeIdentity contains empty TcbLevels");
  }
  try {
    await verifyResponse(
      tcbSigningPhrase,
      collateral.qeIdentityIssuerRootCertificate!,
      collateral.qeIdentityIssuerIntermediateCertificate!,
      collateral.enclaveIdentityBody!,
      collateral.qeIdentity!.signature,
      collateral.rootCaCrl,
      opts,
    );
  } catch (err) {
    throw new Error(`QeIdentity response verification failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// TCB status evaluation against Intel's signed collateral.

function isCPUSvnHigherOrEqual(pckCertCPUSvnComponents: Uint8Array, sgxTcbcomponents: TcbComponent[]): boolean {
  if (pckCertCPUSvnComponents.length !== sgxTcbcomponents.length) return false;
  for (let i = 0; i < pckCertCPUSvnComponents.length; i++) {
    if (pckCertCPUSvnComponents[i] < sgxTcbcomponents[i].svn) return false;
  }
  return true;
}

function isTdxTcbSvnHigherOrEqual(teeTcbSvn: Uint8Array, tdxTcbcomponents: TcbComponent[]): boolean {
  if (teeTcbSvn.length !== tdxTcbcomponents.length) return false;
  let start = 0;
  if (teeTcbSvn[1] > 0) start = 2;
  for (let i = start; i < teeTcbSvn.length; i++) {
    if (teeTcbSvn[i] < tdxTcbcomponents[i].svn) return false;
  }
  return true;
}

function getMatchingTdxModuleTcbLevel(tcbInfoTdxModuleIdentities: TcbInfo["tdxModuleIdentities"], teeTcbSvn: Uint8Array): TcbLevel {
  const tdxModuleIdentityID = tcbInfoTdxModuleIDPrefix + encodeHex(teeTcbSvn.subarray(1, 2));
  const tdxModuleIsvSvn = teeTcbSvn[0];
  for (const tdxModuleIdentity of tcbInfoTdxModuleIdentities) {
    if (tdxModuleIdentityID === tdxModuleIdentity.id) {
      for (const tcbLevel of tdxModuleIdentity.tcbLevels) {
        if (tdxModuleIsvSvn >= tcbLevel.tcb.isvsvn) return tcbLevel;
      }
      throw new Error(`could not find a TDX Module Identity TCB Level matching the TDX Module's ISVSVN (${tdxModuleIsvSvn})`);
    }
  }
  throw new Error(`could not find a TDX Module Identity (${JSON.stringify(tdxModuleIdentityID)}) matching the given TEE TDX version`);
}

function getMatchingTcbLevel(tcbLevels: TcbLevel[], tdReport: TDQuoteBody, pckCertPceSvn: number, pckCertCPUSvnComponents: Uint8Array): TcbLevel {
  for (const tcbLevel of tcbLevels) {
    if (
      isCPUSvnHigherOrEqual(pckCertCPUSvnComponents, tcbLevel.tcb.sgxTcbcomponents) &&
      pckCertPceSvn >= tcbLevel.tcb.pcesvn &&
      isTdxTcbSvnHigherOrEqual(tdReport.teeTcbSvn, tcbLevel.tcb.tdxTcbcomponents)
    ) {
      return tcbLevel;
    }
  }
  throw new Error("no matching TCB level found");
}

function checkQeTcbStatus(tcbLevels: TcbLevel[], isvsvn: number): void {
  for (const tcbLevel of tcbLevels) {
    if (tcbLevel.tcb.isvsvn <= isvsvn) {
      if (tcbLevel.tcbStatus !== TcbComponentStatusUpToDate) {
        throw new Error(`TCB Status is not "UpToDate", found ${JSON.stringify(tcbLevel.tcbStatus)}`);
      }
      return;
    }
  }
  throw new Error("unable to find latest status of TCB, it is now OutOfDate");
}

function checkTcbInfoTcbStatus(tcbInfo: TcbInfo, tdQuoteBody: TDQuoteBody, pckCertExtensions: PckExtensions): void {
  const matchingTcbLevel = getMatchingTcbLevel(tcbInfo.tcbLevels, tdQuoteBody, pckCertExtensions.tcb.pceSvn, pckCertExtensions.tcb.cpuSvnComponents);
  if (tdQuoteBody.teeTcbSvn[1] > 0) {
    const matchingTdxModuleTcbLevel = getMatchingTdxModuleTcbLevel(tcbInfo.tdxModuleIdentities, tdQuoteBody.teeTcbSvn);
    if (matchingTdxModuleTcbLevel.tcbStatus !== TcbComponentStatusUpToDate) {
      throw new Error(`TDX Module TCB Status is not "UpToDate", found ${JSON.stringify(matchingTdxModuleTcbLevel.tcbStatus)}`);
    }
  }
  if (matchingTcbLevel.tcbStatus !== TcbComponentStatusUpToDate) {
    throw new Error(`TCB Status is not "UpToDate", found ${JSON.stringify(matchingTcbLevel.tcbStatus)}`);
  }
}

// Quote body checks against TCB Info and QE Identity (verifyTdQuoteBody /
// verifyQeReport).

function verifyTdQuoteBody(tdQuoteBody: TDQuoteBody, tcbInfo: TcbInfo, pckCertExtensions: PckExtensions): void {
  if (pckCertExtensions.fmspc !== tcbInfo.fmspc) {
    throw new Error(
      `FMSPC from PCK Certificate(${JSON.stringify(pckCertExtensions.fmspc)}) is not equal to FMSPC value from Intel PCS's reported TDX TCB info(${JSON.stringify(tcbInfo.fmspc)})`,
    );
  }
  if (pckCertExtensions.pceid !== tcbInfo.pceId) {
    throw new Error(
      `PCEID from PCK Certificate(${JSON.stringify(pckCertExtensions.pceid)}) is not equal to PCEID value from Intel PCS's reported TDX TCB info(${JSON.stringify(tcbInfo.pceId)})`,
    );
  }
  if (!bytesEqual(tcbInfo.tdxModule.mrsigner, tdQuoteBody.mrSignerSeam)) {
    throw new Error("MRSIGNERSEAM value from TD Quote Body is not equal to TdxModule.Mrsigner field in Intel PCS's reported TDX TCB info");
  }
  if (tcbInfo.tdxModule.attributesMask.length !== tdQuoteBody.seamAttributes.length) {
    throw new Error("size of SeamAttributes from TD Quote Body is not equal to size of TdxModule.AttributesMask in Intel PCS's reported TDX TCB info");
  }
  const attributesMask = applyMask(tcbInfo.tdxModule.attributesMask, tdQuoteBody.seamAttributes);
  if (!bytesEqual(tcbInfo.tdxModule.attributes, attributesMask)) {
    throw new Error("AttributesMask value is not equal to TdxModule.Attributes field in Intel PCS's reported TDX TCB info");
  }
  try {
    checkTcbInfoTcbStatus(tcbInfo, tdQuoteBody, pckCertExtensions);
  } catch (err) {
    throw new Error(`TDX TCB info reported by Intel PCS failed TCB status check: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function verifyQeReport(qeReport: EnclaveReport, qeIdentity: EnclaveIdentity): void {
  if (qeIdentity.miscselectMask.length !== 4) {
    throw new Error(`MISCSELECTMask field size(${qeIdentity.miscselectMask.length}) in Intel PCS's reported QE Identity is not equal to expected size(4)`);
  }
  if (qeIdentity.miscselect.length !== 4) {
    throw new Error(`MISCSELECT field size(${qeIdentity.miscselect.length}) in Intel PCS's reported QE Identity is not equal to expected size(4)`);
  }
  const m = qeIdentity.miscselectMask;
  const miscSelectMaskVal = ((m[0] | (m[1] << 8) | (m[2] << 16) | (m[3] << 24)) >>> 0) & qeReport.miscSelect;
  const s = qeIdentity.miscselect;
  const miscSelect = (s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24)) >>> 0;
  if ((miscSelectMaskVal >>> 0) !== miscSelect) {
    throw new Error(`MISCSELECT value(${miscSelect}) from Intel PCS's reported QE Identity is not equal to MISCSELECTMask value(${miscSelectMaskVal >>> 0})`);
  }

  if (qeIdentity.attributesMask.length !== qeReport.attributes.length) {
    throw new Error("size of AttributesMask value in Intel PCS's reported QE Identity is not equal to size of Attributes value in QE Report");
  }
  const qeAttributesMask = applyMask(qeIdentity.attributesMask, qeReport.attributes);
  if (!bytesEqual(qeIdentity.attributes, qeAttributesMask)) {
    throw new Error("AttributesMask value is not equal to Attributes value in Intel PCS's reported QE Identity");
  }

  if (!bytesEqual(qeIdentity.mrsigner, qeReport.mrSigner)) {
    throw new Error("MRSIGNER value in QE Report is not equal to MRSIGNER value in Intel PCS's reported QE Identity");
  }

  if (qeReport.isvProdId !== qeIdentity.isvProdID) {
    throw new Error(
      `ISV PRODID value(${qeReport.isvProdId}) in QE Report is not equal to ISV PRODID value(${qeIdentity.isvProdID}) in Intel PCS's reported QE Identity`,
    );
  }

  try {
    checkQeTcbStatus(qeIdentity.tcbLevels, qeReport.isvSvn);
  } catch (err) {
    throw new Error(`QE Identity reported by Intel PCS failed TCB status check: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// Quote signature verification (verifyQuote).

async function verifyHash256(quote: QuoteV4): Promise<void> {
  const qeReportCertificationData = quote.signedData.certificationData.qeReportCertificationData;
  const qeReportData = qeReportCertificationData.qeReport.reportData;
  const qeAuthData = qeReportCertificationData.qeAuthData.data;
  const attestKey = quote.signedData.ecdsaAttestationKey;

  const hashed = await sha256(attestKey, qeAuthData);
  const hashedMessage = new Uint8Array(qeReportData.length);
  hashedMessage.set(hashed, 0);
  if (!bytesEqual(hashedMessage, qeReportData)) {
    throw new Error(
      "QE Report Data does not match with value of SHA 256 calculated over the concatenation of ECDSA Attestation Key and QE Authenticated Data",
    );
  }
}

async function verifyQuote(quote: QuoteV4, chain: PCKCertificateChain, collateral: Collateral, pckCertExtensions: PckExtensions): Promise<void> {
  let attestPublicKey: Uint8Array;
  try {
    attestPublicKey = await ecdsaP256PublicKey(quote.signedData.ecdsaAttestationKey);
  } catch (err) {
    throw new Error(`attestation key in the quote is invalid: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!(await verifyRawSignature(quote.headerAndBody, quote.signedData.signature, attestPublicKey))) {
    throw new Error("unable to verify message digest using quote's signature and ecdsa attestation key");
  }

  const qeReportCertificationData = quote.signedData.certificationData.qeReportCertificationData;
  if (!(await verifyRawSignature(qeReportCertificationData.qeReportRaw, qeReportCertificationData.qeReportSignature, chain.pckCertificate.spkiDER))) {
    throw new Error("error verifying QE report signature: QE report's signature verification using PCK Leaf Certificate failed");
  }

  try {
    await verifyHash256(quote);
  } catch (err) {
    throw new Error(`error verifying QE report data: ${err instanceof Error ? err.message : String(err)}`);
  }

  verifyTdQuoteBody(quote.tdQuoteBody, collateral.tdxTcbInfo!.tcbInfo, pckCertExtensions);
  verifyQeReport(qeReportCertificationData.qeReport, collateral.qeIdentity!.enclaveIdentity);
}

// tdxVerifyQuoteV4 mirrors tdxverify.TdxQuote for a parsed quote v4 under
// this configuration: replayed collateral, pinned root, revocations checked,
// validity at opts.now.
export async function tdxVerifyQuoteV4(quote: QuoteV4, opts: VerifyOptions): Promise<void> {
  const chain = extractChainFromQuoteV4(quote);
  let exts: PckExtensions;
  try {
    exts = pckCertificateExtensions(chain.pckCertificate);
  } catch (err) {
    throw new Error(`could not get PCK certificate extensions: ${err instanceof Error ? err.message : String(err)}`);
  }
  const ca = extractCaFromPckCert(chain.pckCertificate);
  const collateral = obtainCollateral(exts.fmspc, ca, opts.getter);

  await verifyPCKCertificationChain(chain, collateral, opts);
  try {
    verifyCollateral(collateral, opts.now);
  } catch (err) {
    throw new Error(`could not verify collaterals obtained: ${err instanceof Error ? err.message : String(err)}`);
  }
  await verifyTCBinfo(collateral, opts);
  await verifyQeIdentity(collateral, opts);
  await verifyQuote(quote, chain, collateral, exts);
}
