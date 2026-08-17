// AMD SEV-SNP report authentication against the pinned AMD roots, a 1:1
// port of Go verifier/quote/sev/authenticate.go plus the checks the
// configured go-sev-guest verify.SnpAttestation options perform
// (offline getter, revocations on, pinned Genoa roots, product from the
// report's CPUID FMS, pinned clock). Every rejection throws
// VerificationError("QUOTE_REJECTED", ...).

import { decodeBase64, encodeHex } from "../bytes.js";
import { VerificationError } from "../errors.js";
import {
  CollateralAMDCRLV1Format,
  CollateralAMDVCEKV1Format,
  endorsementCollateral,
  parseAMDCRLCollateral,
  parseAMDVCEKCollateral,
  SubjectCPU,
  type Document,
} from "../envelope.js";
import { SevGuestV2, type Measurement } from "../measurement.js";
import { genoaCertChainPEM } from "../embedded/roots.js";
import {
  NoneReportSigner,
  parseReport,
  parseSignerInfo,
  productLineFromFms,
  ReportSize,
  reportSignerString,
  reportToSignatureDER,
  signedComponent,
  SignEcdsaP384Sha384,
  validateReportFormat,
  VcekReportSigner,
  VlekReportSigner,
  type SevReport,
} from "./abi.js";
import { identity } from "./identity.js";
import { vcekCertificateExtensions } from "./kds.js";
import {
  derBytesEqual,
  isPSSSHA384,
  keyUsageCertSign,
  keyUsageCRLSign,
  oidCommonName,
  oidCountry,
  oidECPublicKey,
  oidLocality,
  oidOrganization,
  oidOrganizationalUnit,
  oidP384,
  oidProvince,
  parseCertificate,
  parseCRL,
  pemDecode,
  verifyECDSASHA384DER,
  verifyPSSSHA384,
  type Certificate,
  type CRL,
} from "./x509.js";

// ProductGenoa is the only AMD product line currently supported.
export const ProductGenoa = "Genoa";

export interface QuoteOpts {
  rootPEM?: string; // ASK+ARK KDS chain; default: embedded Genoa root
  now?: Date; // validity-window clock; default: current time
}

// SevQuote is a signature-verified SEV-SNP report, not yet compared against
// any expected value (Go sev.Quote).
export interface SevQuote {
  // identity is the machines-map lookup key (CHIP_ID, lowercase hex).
  identity: string;
  // measurement is the launch measurement register.
  measurement: Measurement;
  report: SevReport;
  // Retained for policy assembly (Go: Quote.attestation).
  productLine: string;
  vcek: Certificate;
}

function quoteError(message: string): VerificationError {
  return new VerificationError("QUOTE_REJECTED", message);
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// trustedRoots parses the pinned AMD trust anchor (ASK+ARK KDS cert_chain
// PEM). A fresh parse per authentication: document-supplied collateral must
// never affect other verifications (Go trustedRoots + trust.FromKDSCertBytes).
interface AMDRoots {
  ask?: Certificate; // undefined when the intermediate is an ASVK
  asvk?: Certificate;
  ark: Certificate;
}

function trustedRoots(rootPEM: string): AMDRoots {
  // kds.ParseProductCertChain: exactly two CERTIFICATE PEM blocks, ASK then
  // ARK, no trailing bytes.
  const askBlock = pemDecode(rootPEM);
  if (askBlock === undefined || askBlock.type !== "CERTIFICATE") {
    throw new Error("parsing embedded AMD Genoa root certificates: could not find ASK or ASVK PEM block");
  }
  const arkBlock = pemDecode(askBlock.rest);
  if (arkBlock === undefined || arkBlock.type !== "CERTIFICATE") {
    throw new Error("parsing embedded AMD Genoa root certificates: could not find ARK PEM block");
  }
  if (arkBlock.rest.length !== 0) {
    throw new Error(`parsing embedded AMD Genoa root certificates: unexpected trailing bytes: ${arkBlock.rest.length} bytes`);
  }
  let ica: Certificate;
  try {
    ica = parseCertificate(askBlock.der);
  } catch (err) {
    throw new Error(`parsing embedded AMD Genoa root certificates: could not parse intermediate certificate: ${errMsg(err)}`);
  }
  let ark: Certificate;
  try {
    ark = parseCertificate(arkBlock.der);
  } catch (err) {
    throw new Error(`parsing embedded AMD Genoa root certificates: could not parse ARK certificate: ${errMsg(err)}`);
  }
  // trust.ProductCerts.Decode: an SEV-VLEK intermediate is the ASVK.
  const cn = (ica.subject.get(oidCommonName) ?? [""])[0];
  if (cn.startsWith("SEV-VLEK")) {
    return { asvk: ica, ark };
  }
  return { ask: ica, ark };
}

// decodeCertChain decodes the document-carried ASK+ARK PEM chain (the AMD
// KDS cert_chain format). The chain is untrusted transport: verification
// runs against the pinned AMD root certificates (Go decodeCertChain).
export function decodeCertChain(chainPEM: string): { askDER: Uint8Array; arkDER: Uint8Array } {
  let rest = chainPEM;
  const blocks: Uint8Array[] = [];
  for (;;) {
    const block = pemDecode(rest);
    if (block === undefined) break;
    if (block.type !== "CERTIFICATE") {
      throw new Error(`cert_chain_pem carries a ${JSON.stringify(block.type)} block, want CERTIFICATE`);
    }
    if (block.der.length === 0) {
      throw new Error("cert_chain_pem carries an empty CERTIFICATE block");
    }
    blocks.push(block.der);
    rest = block.rest;
  }
  if (blocks.length !== 2) {
    throw new Error(`cert_chain_pem must carry exactly the ASK and ARK certificates, got ${blocks.length} blocks`);
  }
  if (rest.trim().length !== 0) {
    throw new Error("cert_chain_pem carries trailing data after the certificates");
  }
  return { askDER: blocks[0], arkDER: blocks[1] };
}

// validateAmdLocation checks the exact AMD KDS subject/issuer location
// fields (Go verify.validateAmdLocation).
function validateAmdLocation(name: Map<string, string[]>, role: string): void {
  const checkSingletonList = (oid: string, fieldName: string, names: string, value: string): void => {
    const l = name.get(oid) ?? [];
    if (l.length !== 1) {
      throw new Error(`${role} has ${l.length} ${names}, want 1`);
    }
    if (l[0] !== value) {
      throw new Error(`${role} ${fieldName} '${l[0]}' not expected for AMD. Expected '${value}'`);
    }
  };
  checkSingletonList(oidCountry, "country", "countries", "US");
  checkSingletonList(oidLocality, "locality", "localities", "Santa Clara");
  checkSingletonList(oidProvince, "state", "states", "CA");
  checkSingletonList(oidOrganization, "organization", "organizations", "Advanced Micro Devices");
  checkSingletonList(oidOrganizationalUnit, "organizational unit", "organizational units", "Engineering");
}

function commonName(name: Map<string, string[]>): string {
  return (name.get(oidCommonName) ?? [""])[0] ?? "";
}

// validateKDSCertificateProductNonspecific checks the documented qualities
// of a VCEK certificate per the KDS specification (Go
// verify.validateKDSCertificateProductNonspecific for the VCEK signer).
function validateKDSCertificateProductNonspecific(cert: Certificate): void {
  if (cert.version !== 3) {
    throw new Error(`VCEK certificate version is ${cert.version}, expected 3`);
  }
  if (!isPSSSHA384(cert.signatureAlgorithm)) {
    throw new Error("VCEK certificate signature algorithm is not SHA-384 with RSASSA-PSS");
  }
  if (cert.spkiAlgorithmOID !== oidECPublicKey) {
    throw new Error("VCEK certificate public key type is not ECDSA");
  }
  if (cert.spkiCurveOID !== oidP384) {
    throw new Error(`VCEK certificate public key curve is ${cert.spkiCurveOID}, expected P-384`);
  }
  validateAmdLocation(cert.subject, "VCEK subject");
  const want = "SEV-VCEK";
  if (commonName(cert.subject) !== want) {
    throw new Error(`VCEK certificate subject common name ${commonName(cert.subject)} not expected. Expected ${want}`);
  }
  vcekCertificateExtensions(cert); // wellformedness; product name unchecked with a known product line
}

// validateKDSCertIssuer checks the KDS-specified issuer metadata (Go
// verify.validateKDSCertIssuer).
function validateKDSCertIssuer(cert: Certificate, productLine: string): void {
  validateAmdLocation(cert.issuer, "VCEK issuer");
  const cn = `SEV-${productLine}`;
  if (commonName(cert.issuer) !== cn) {
    throw new Error(`VCEK certificate issuer common name ${commonName(cert.issuer)} not expected. Expected ${cn}`);
  }
}

// checkValidity mirrors Go x509 isValid's window check against opts.Now.
function checkValidity(cert: Certificate, now: Date, role: string): void {
  if (now.getTime() < cert.notBefore.getTime() || now.getTime() > cert.notAfter.getTime()) {
    throw new Error(`${role} certificate has expired or is not yet valid`);
  }
}

// checkCASignerConstraints mirrors Go x509 CheckSignatureFrom / isValid CA
// constraints for a signing parent: basic constraints and key usage.
function checkCASignerConstraints(parent: Certificate, usageBit: number, role: string): void {
  if ((parent.version === 3 && !parent.basicConstraintsValid) || (parent.basicConstraintsValid && !parent.isCA)) {
    throw new Error(`${role} certificate is not a certificate authority`);
  }
  if (parent.keyUsage !== 0 && (parent.keyUsage & usageBit) === 0) {
    throw new Error(`${role} certificate key usage does not permit signing`);
  }
}

// verifyChain mirrors x509 Certificate.Verify with Roots={ARK},
// Intermediates={ASK}, CurrentTime=now: raw-DER name chaining, RSA-PSS
// SHA-384 signatures, validity windows, and CA constraints. The ARK
// self-signature is additionally verified (the trust anchor is repo-pinned,
// not system-provided).
function verifyChain(vcek: Certificate, roots: AMDRoots, now: Date): void {
  const ica = roots.ask;
  if (ica === undefined) {
    throw new Error("root of trust missing intermediate certificate authority certificate for key VCEK");
  }
  const ark = roots.ark;
  checkValidity(vcek, now, "VCEK");

  if (!derBytesEqual(vcek.issuerDER, ica.subjectDER)) {
    throw new Error("error verifying VCEK certificate: certificate signed by unknown authority");
  }
  checkValidity(ica, now, "ASK");
  checkCASignerConstraints(ica, keyUsageCertSign, "ASK");
  if (!isPSSSHA384(vcek.signatureAlgorithm) || !verifyPSSSHA384(vcek.tbs, vcek.signature, ica.publicKey)) {
    throw new Error("error verifying VCEK certificate: not signed by the ASK");
  }

  if (!derBytesEqual(ica.issuerDER, ark.subjectDER)) {
    throw new Error("error verifying ASK certificate: certificate signed by unknown authority");
  }
  checkValidity(ark, now, "ARK");
  checkCASignerConstraints(ark, keyUsageCertSign, "ARK");
  if (!isPSSSHA384(ica.signatureAlgorithm) || !verifyPSSSHA384(ica.tbs, ica.signature, ark.publicKey)) {
    throw new Error("error verifying ASK certificate: not signed by the ARK");
  }

  if (!derBytesEqual(ark.issuerDER, ark.subjectDER)) {
    throw new Error("error verifying ARK certificate: not self-issued");
  }
  if (!isPSSSHA384(ark.signatureAlgorithm) || !verifyPSSSHA384(ark.tbs, ark.signature, ark.publicKey)) {
    throw new Error("error verifying ARK certificate: not properly self-signed");
  }
}

// checkRevocation mirrors verify.GetCrlAndCheckRoot fed by the offline
// getter: the CRL must be reachable from the pinned ASK's distribution
// points, be signed by the pinned ARK, and revoke neither the ASK nor the
// VCEK. Fail-closed: any miss rejects (the VCEK-serial check is a
// fail-closed extension of the library's ASK-only check).
function checkRevocation(roots: AMDRoots, vcek: Certificate, crl: CRL): void {
  const ask = roots.ask;
  if (ask === undefined) {
    throw new Error("missing ASK x509 certificate to check intermediate key validity");
  }
  // offlineGetter answers only URLs whose path ends in /crl.
  const served = ask.crlDistributionPoints.some((url) => {
    try {
      return new URL(url).pathname.endsWith("/crl");
    } catch {
      return false;
    }
  });
  if (!served) {
    throw new Error("could not fetch product CRL");
  }
  // verifyCRL: signed by the ARK (Go CRL.CheckSignatureFrom).
  checkCASignerConstraints(roots.ark, keyUsageCRLSign, "ARK");
  if (!isPSSSHA384(crl.signatureAlgorithm) || !verifyPSSSHA384(crl.tbs, crl.signature, roots.ark.publicKey)) {
    throw new Error("CRL is not signed by ARK");
  }
  for (const bad of crl.revokedSerialsHex) {
    if (bad === ask.serialHex) {
      throw new Error("ASK was revoked");
    }
    if (bad === vcek.serialHex) {
      throw new Error("VCEK was revoked");
    }
  }
}

// productFromReport derives the SEV product line from the report's CPUID
// family/model/stepping field, present since report version 3 (Go
// productFromReport + abi.SevProductFromCpuid1Eax).
function productLineFromReport(report: SevReport): string {
  if (report.cpuid1EaxFms === 0) {
    throw new Error(`report carries no CPUID product identity (report version ${report.version}, want 3+)`);
  }
  return productLineFromFms(report.cpuid1EaxFms);
}

// rejectMaskedChipID rejects reports whose SIGNER_INFO masks the CHIP_ID:
// masked platform identities cannot be endorsed (Go rejectMaskedChipID).
export function rejectMaskedChipID(report: SevReport): void {
  let signer;
  try {
    signer = parseSignerInfo(report.signerInfo);
  } catch (err) {
    throw quoteError(`parsing report SIGNER_INFO: ${errMsg(err)}`);
  }
  if (signer.maskChipKey) {
    throw quoteError("report masks CHIP_ID; masked platform identities are unsupported");
  }
}

// verifySignature verifies the report signature under the AMD roots with
// the provided VCEK, checking revocation against the provided CRL. No
// policy validation (Go verifySignature + verify.SnpAttestation with the
// options set in authenticate.go).
function verifySignature(
  reportBase64: string,
  vcekDER: Uint8Array,
  crl: CRL,
  rootPEM: string,
  now: Date,
): { report: SevReport; productLine: string; vcek: Certificate } {
  let reportBytes: Uint8Array;
  try {
    reportBytes = decodeBase64(reportBase64);
  } catch (err) {
    throw quoteError(errMsg(err));
  }
  if (reportBytes.length !== ReportSize) {
    throw quoteError(`SEV-SNP report must be exactly ${ReportSize} bytes, got ${reportBytes.length}`);
  }

  let report: SevReport;
  try {
    report = parseReport(reportBytes);
  } catch (err) {
    throw quoteError(`failed to parse report: ${errMsg(err)}`);
  }

  let productLine: string;
  let roots: AMDRoots;
  try {
    productLine = productLineFromReport(report);
    roots = trustedRoots(rootPEM);
  } catch (err) {
    throw quoteError(errMsg(err));
  }

  try {
    // fillInAttestation: the certificate chain is complete, so the only
    // reachable check is the VLEK signer with no VLEK certificate.
    const info = parseSignerInfo(report.signerInfo);
    if (info.signingKey === VlekReportSigner) {
      throw new Error("report signed with VLEK, but VLEK certificate is missing");
    }
    if (info.signingKey !== VcekReportSigner) {
      throw new Error(`missing ${reportSignerString(info.signingKey)} certificate`);
    }
  } catch (err) {
    throw quoteError(errMsg(err));
  }

  // decodeCerts: VCEK wellformedness, then verification against the pinned
  // Genoa roots (the only product line with a trusted root).
  let vcek: Certificate;
  try {
    vcek = parseCertificate(vcekDER);
  } catch (err) {
    throw quoteError(`could not interpret VCEK DER bytes: ${errMsg(err)}`);
  }
  try {
    validateKDSCertificateProductNonspecific(vcek);
  } catch (err) {
    throw quoteError(errMsg(err));
  }
  if (productLine !== ProductGenoa) {
    throw quoteError(`VCEK could not be verified by any trusted roots. Product line ${JSON.stringify(productLine)}`);
  }
  try {
    validateKDSCertIssuer(vcek, ProductGenoa);
    verifyChain(vcek, roots, now);
  } catch (err) {
    throw quoteError(errMsg(err));
  }

  // CheckRevocations against the document-carried CRL, fail-closed.
  try {
    checkRevocation(roots, vcek, crl);
  } catch (err) {
    throw quoteError(errMsg(err));
  }

  // SnpReportSignature: format check, then ECDSA-P384-SHA384 over the
  // signed component with little-endian r||s converted to DER.
  try {
    validateReportFormat(reportBytes);
  } catch (err) {
    throw quoteError(`attestation report format error: ${errMsg(err)}`);
  }
  if (report.signatureAlgo !== SignEcdsaP384Sha384) {
    throw quoteError(`unknown SignatureAlgo: ${report.signatureAlgo}`);
  }
  let sigDER: Uint8Array;
  try {
    sigDER = reportToSignatureDER(reportBytes);
  } catch (err) {
    throw quoteError(`could not interpret report signature: ${errMsg(err)}`);
  }
  if (!verifyECDSASHA384DER(signedComponent(reportBytes), sigDER, vcek.publicKey)) {
    throw quoteError("report signature verification error");
  }

  return { report, productLine, vcek };
}

// sevAuthenticate verifies the report's signature chain up to the pinned
// AMD root and its VCEK against the document-carried CRL — no network
// fetches. Callers must assemble a policy and validate before trusting the
// platform (Go sev.Authenticate).
export async function sevAuthenticate(doc: Document, opts?: QuoteOpts): Promise<SevQuote> {
  const rootPEM = opts?.rootPEM ?? genoaCertChainPEM;
  const now = opts?.now ?? new Date();

  const entry = endorsementCollateral(doc, CollateralAMDVCEKV1Format, SubjectCPU);
  if (entry === undefined) {
    throw quoteError("document carries no amd-vcek endorsement collateral for the cpu");
  }
  const data = parseAMDVCEKCollateral(entry.data);
  let vcekDER: Uint8Array;
  try {
    vcekDER = decodeBase64(data.vcekDerBase64);
  } catch (err) {
    throw quoteError(`decoding vcek_der_base64: ${errMsg(err)}`);
  }
  // An empty VCEK would otherwise read as a fetch request.
  if (vcekDER.length === 0) {
    throw quoteError(`amd-vcek collateral entry ${JSON.stringify(entry.id)} carries an empty VCEK`);
  }
  try {
    decodeCertChain(data.certChainPem);
  } catch (err) {
    throw quoteError(`amd-vcek collateral entry ${JSON.stringify(entry.id)}: ${errMsg(err)}`);
  }

  const crlEntry = endorsementCollateral(doc, CollateralAMDCRLV1Format, SubjectCPU);
  if (crlEntry === undefined) {
    throw quoteError("document carries no amd-crl endorsement collateral for the cpu");
  }
  const crlData = parseAMDCRLCollateral(crlEntry.data);
  let crlDER: Uint8Array;
  try {
    crlDER = decodeBase64(crlData.crlDerBase64);
  } catch (err) {
    throw quoteError(`decoding crl_der_base64: ${errMsg(err)}`);
  }
  if (crlDER.length === 0) {
    throw quoteError(`amd-crl collateral entry ${JSON.stringify(crlEntry.id)} carries an empty CRL`);
  }
  // The chain check verifies the CRL's signature but not its validity
  // window, so a stale pre-revocation CRL would otherwise pass.
  let parsedCRL: CRL;
  try {
    parsedCRL = parseCRL(crlDER);
  } catch (err) {
    throw quoteError(`parsing amd-crl collateral: ${errMsg(err)}`);
  }
  if (now.getTime() < parsedCRL.thisUpdate.getTime() || now.getTime() > parsedCRL.nextUpdate.getTime()) {
    throw quoteError(
      `amd-crl collateral is outside its validity window (this_update ${parsedCRL.thisUpdate.toISOString()}, next_update ${parsedCRL.nextUpdate.toISOString()})`,
    );
  }

  const { report, productLine, vcek } = verifySignature(doc.cpuEvidence.reportBase64, vcekDER, parsedCRL, rootPEM, now);
  rejectMaskedChipID(report);

  let id: string;
  try {
    id = identity(report.chipId);
  } catch (err) {
    throw quoteError(errMsg(err));
  }

  return {
    identity: id,
    measurement: { type: SevGuestV2, registers: [encodeHex(report.measurement)] },
    report,
    productLine,
    vcek,
  };
}
