import type { Report } from './report.js';
import type { TCBParts } from './types.js';
import { ReportSigner } from './constants.js';
import { ARK_CERT, ASK_CERT } from './certs.js';
import { tcbFromInt, bytesToHex } from './utils.js';
import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { ASN1Obj, uint8ArrayEqual } from '@freedomofpress/crypto-browser';
import { FetchError, AttestationError, wrapOrThrow } from '../errors.js';

// SEV-SNP VCEK OID definitions
const SnpOid = {
  STRUCT_VERSION: '1.3.6.1.4.1.3704.1.1',
  PRODUCT_NAME: '1.3.6.1.4.1.3704.1.2',
  BL_SPL: '1.3.6.1.4.1.3704.1.3.1',
  TEE_SPL: '1.3.6.1.4.1.3704.1.3.2',
  SNP_SPL: '1.3.6.1.4.1.3704.1.3.3',
  SPL4: '1.3.6.1.4.1.3704.1.3.4',
  SPL5: '1.3.6.1.4.1.3704.1.3.5',
  SPL6: '1.3.6.1.4.1.3704.1.3.6',
  SPL7: '1.3.6.1.4.1.3704.1.3.7',
  UCODE: '1.3.6.1.4.1.3704.1.3.8',
  HWID: '1.3.6.1.4.1.3704.1.4',
  CSP_ID: '1.3.6.1.4.1.3704.1.5',
  // Aliases for compatibility
  BOOTLOADER: '1.3.6.1.4.1.3704.1.3.1',
  TEE: '1.3.6.1.4.1.3704.1.3.2',
  SNP: '1.3.6.1.4.1.3704.1.3.3',
};

// OIDs for signature and key algorithms
const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_SECP384R1 = '1.3.132.0.34';

export class CertificateChain {
  constructor(
    public ark: X509Certificate,
    public ask: X509Certificate,
    public vcek: X509Certificate
  ) {}

  static async fromReport(report: Report, vcekDer?: Uint8Array): Promise<CertificateChain> {
    // Validate report
    if (report.productName !== 'Genoa') {
      throw new AttestationError(`Unsupported processor: ${report.productName}. This verifier only supports AMD EPYC Genoa processors`);
    }

    if (report.signerInfoParsed.signingKey !== ReportSigner.VcekReportSigner) {
      throw new AttestationError('Unsupported signing key: This verifier only supports VCEK-signed attestation reports');
    }

    // Fetch VCEK if not provided
    const vcek = vcekDer ?? await this.fetchVcekForReport(report);

    const ark = X509Certificate.parse(ARK_CERT);
    const ask = X509Certificate.parse(ASK_CERT);
    const vcekCert = X509Certificate.parse(vcek);

    return new CertificateChain(ark, ask, vcekCert);
  }

  private static async fetchVcekForReport(report: Report): Promise<Uint8Array> {
    const vcekUrl = buildVCEKUrl(report.productName, report.chipId, report.reportedTcb);

    const isBrowser = typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
    if (isBrowser) { // Browser supports local caching
      const cached = localStorage.getItem(vcekUrl);
      if (cached) {
        try { // Base64 decode and return as Uint8Array
          return Uint8Array.from(atob(cached), c => c.charCodeAt(0));
        } catch { // Base64 decode failed, remove from cache
          localStorage.removeItem(vcekUrl);
        }
      }
      return fetchAndCacheVCEK(vcekUrl);
    }

    return fetchVCEK(vcekUrl);
  }

  async verifyChain(): Promise<boolean> {
    try {
      // Validate certificate formats
      this.validateArkFormat();
      this.validateAskFormat();
      this.validateVcekFormat();

      // Validate certificate validity periods
      const now = new Date();
      if (!this.ark.validForDate(now)) {
        throw new AttestationError('AMD Root Key (ARK) certificate has expired or is not yet valid');
      }
      if (!this.ask.validForDate(now)) {
        throw new AttestationError('AMD SEV Key (ASK) certificate has expired or is not yet valid');
      }
      if (!this.vcek.validForDate(now)) {
        throw new AttestationError('VCEK certificate has expired or is not yet valid');
      }

      // Verify signature chain: ARK self-signed, ARK signs ASK, ASK signs VCEK
      const arkSelfSigned = await this.ark.verify();
      if (!arkSelfSigned) {
        throw new AttestationError('AMD Root Key (ARK) certificate signature verification failed: Not properly self-signed');
      }

      const askSignedByArk = await this.ask.verify(this.ark);
      if (!askSignedByArk) {
        throw new AttestationError('AMD SEV Key (ASK) certificate signature verification failed: Not signed by ARK');
      }

      const vcekSignedByAsk = await this.vcek.verify(this.ask);
      if (!vcekSignedByAsk) {
        throw new AttestationError('VCEK certificate signature verification failed: Not signed by ASK');
      }

      return true;
    } catch (e) {
      wrapOrThrow(e, AttestationError, 'AMD certificate chain verification failed');
    }
  }

  validateVcekTcb(tcb: TCBParts): void {
    // Validate BL_SPL
    const blSplExt = this.vcek.extension(SnpOid.BL_SPL);
    if (!blSplExt) {
      throw new AttestationError('Invalid VCEK certificate: Missing bootloader security patch level (BL_SPL) extension');
    }
    const blSpl = this.decodeExtensionInteger(blSplExt.value);
    if (blSpl !== tcb.blSpl) {
      throw new AttestationError(`VCEK TCB mismatch: Bootloader SPL in certificate (${blSpl}) does not match report (${tcb.blSpl})`);
    }

    // Validate TEE_SPL
    const teeSplExt = this.vcek.extension(SnpOid.TEE_SPL);
    if (!teeSplExt) {
      throw new AttestationError('Invalid VCEK certificate: Missing TEE security patch level (TEE_SPL) extension');
    }
    const teeSpl = this.decodeExtensionInteger(teeSplExt.value);
    if (teeSpl !== tcb.teeSpl) {
      throw new AttestationError(`VCEK TCB mismatch: TEE SPL in certificate (${teeSpl}) does not match report (${tcb.teeSpl})`);
    }

    // Validate SNP_SPL
    const snpSplExt = this.vcek.extension(SnpOid.SNP_SPL);
    if (!snpSplExt) {
      throw new AttestationError('Invalid VCEK certificate: Missing SNP security patch level (SNP_SPL) extension');
    }
    const snpSpl = this.decodeExtensionInteger(snpSplExt.value);
    if (snpSpl !== tcb.snpSpl) {
      throw new AttestationError(`VCEK TCB mismatch: SNP SPL in certificate (${snpSpl}) does not match report (${tcb.snpSpl})`);
    }

    // Validate UCODE
    const ucodeExt = this.vcek.extension(SnpOid.UCODE);
    if (!ucodeExt) {
      throw new AttestationError('Invalid VCEK certificate: Missing microcode security patch level (UCODE) extension');
    }
    const ucodeSpl = this.decodeExtensionInteger(ucodeExt.value);
    if (ucodeSpl !== tcb.ucodeSpl) {
      throw new AttestationError(`VCEK TCB mismatch: Microcode SPL in certificate (${ucodeSpl}) does not match report (${tcb.ucodeSpl})`);
    }
  }

  validateVcekHwid(chipId: Uint8Array): void {
    const hwidExt = this.vcek.extension(SnpOid.HWID);
    if (!hwidExt) {
      throw new AttestationError('Invalid VCEK certificate: Missing hardware ID (HWID) extension');
    }

    // The HWID extension value is the raw chip ID bytes
    if (!uint8ArrayEqual(hwidExt.value, chipId)) {
      throw new AttestationError('VCEK hardware ID mismatch: Certificate HWID does not match the chip ID in the attestation report');
    }
  }

  private validateArkFormat(): void {
    // Validate certificate version (must be v3)
    if (this.ark.version !== 'v3') {
      throw new AttestationError(`Invalid ARK certificate: Expected X.509 version v3, got ${this.ark.version}`);
    }

    // Validate AMD location for issuer and subject
    if (!this.validateAmdLocation(this.ark.issuerDN)) {
      throw new AttestationError('Invalid ARK certificate: Issuer is not a valid AMD organization');
    }
    if (!this.validateAmdLocation(this.ark.subjectDN)) {
      throw new AttestationError('Invalid ARK certificate: Subject is not a valid AMD organization');
    }

    // Check common name
    const cn = this.ark.subjectDN.get('CN');
    if (cn !== 'ARK-Genoa') {
      throw new AttestationError(`Invalid ARK certificate: Expected common name "ARK-Genoa", got "${cn}"`);
    }
  }

  private validateAskFormat(): void {
    // Validate certificate version (must be v3)
    if (this.ask.version !== 'v3') {
      throw new AttestationError(`Invalid ASK certificate: Expected X.509 version v3, got ${this.ask.version}`);
    }

    // Validate AMD location
    if (!this.validateAmdLocation(this.ask.issuerDN)) {
      throw new AttestationError('Invalid ASK certificate: Issuer is not a valid AMD organization');
    }
    if (!this.validateAmdLocation(this.ask.subjectDN)) {
      throw new AttestationError('Invalid ASK certificate: Subject is not a valid AMD organization');
    }

    // Check common name is exactly "SEV-Genoa" (ASK cert uses SEV-Genoa)
    const cn = this.ask.subjectDN.get('CN');
    if (cn !== 'SEV-Genoa') {
      throw new AttestationError(`Invalid ASK certificate: Expected common name "SEV-Genoa", got "${cn}"`);
    }
  }

  private validateVcekFormat(): void {
    // Validate certificate version (must be v3)
    if (this.vcek.version !== 'v3') {
      throw new AttestationError(`Invalid VCEK certificate: Expected X.509 version v3, got ${this.vcek.version}`);
    }

    // Validate AMD location
    if (!this.validateAmdLocation(this.vcek.issuerDN)) {
      throw new AttestationError('Invalid VCEK certificate: Issuer is not a valid AMD organization');
    }
    if (!this.validateAmdLocation(this.vcek.subjectDN)) {
      throw new AttestationError('Invalid VCEK certificate: Subject is not a valid AMD organization');
    }

    // Validate common name
    const cn = this.vcek.subjectDN.get('CN');
    if (cn !== 'SEV-VCEK') {
      throw new AttestationError(`Invalid VCEK certificate: Expected common name "SEV-VCEK", got "${cn}"`);
    }

    // Validate signature algorithm (must be RSASSA-PSS for VCEK signed by ASK)
    const sigAlgOid = this.getSignatureAlgorithmOid(this.vcek);
    if (sigAlgOid !== OID_RSASSA_PSS) {
      throw new AttestationError('Invalid VCEK certificate: Signature algorithm must be RSASSA-PSS');
    }

    // Validate public key algorithm and curve
    const { algorithm, curve } = this.getPublicKeyInfo(this.vcek);
    if (algorithm !== OID_EC_PUBLIC_KEY) {
      throw new AttestationError('Invalid VCEK certificate: Public key must be ECDSA');
    }
    if (curve !== OID_SECP384R1) {
      throw new AttestationError('Invalid VCEK certificate: Public key curve must be secp384r1 (P-384)');
    }

    // CSP_ID must NOT be present (critical for VCEK vs VLEK distinction)
    const cspIdExt = this.vcek.extension(SnpOid.CSP_ID);
    if (cspIdExt) {
      throw new AttestationError('Invalid VCEK certificate: CSP_ID extension should not be present (this looks like a VLEK certificate)');
    }

    // HWID must be present and correct length
    const hwidExt = this.vcek.extension(SnpOid.HWID);
    if (!hwidExt || hwidExt.value.length !== 64) {
      throw new AttestationError('Invalid VCEK certificate: Missing or malformed hardware ID (HWID) extension');
    }

    // Product name validation
    const productNameExt = this.vcek.extension(SnpOid.PRODUCT_NAME);
    if (!productNameExt) {
      throw new AttestationError('Invalid VCEK certificate: Missing product name extension');
    }
    // The extension value should be DER-encoded IA5String: tag 0x16, length 0x05, value "Genoa"
    const expectedProductName = new Uint8Array([0x16, 0x05, 0x47, 0x65, 0x6e, 0x6f, 0x61]);
    if (!uint8ArrayEqual(productNameExt.value, expectedProductName)) {
      throw new AttestationError('Invalid VCEK certificate: Product name must be "Genoa"');
    }
  }

  private validateAmdLocation(name: Map<string, string>): boolean {
    const country = name.get('C');
    const locality = name.get('L');
    const state = name.get('ST');
    const org = name.get('O');
    const orgUnit = name.get('OU');

    return (
      country === 'US' &&
      locality === 'Santa Clara' &&
      state === 'CA' &&
      org === 'Advanced Micro Devices' &&
      orgUnit === 'Engineering'
    );
  }

  private getSignatureAlgorithmOid(cert: X509Certificate): string {
    // signatureAlgorithm is the second element of the certificate sequence
    const sigAlgObj = cert.root.subs[1];
    return sigAlgObj.subs[0].toOID();
  }

  private getPublicKeyInfo(cert: X509Certificate): { algorithm: string; curve: string } {
    // subjectPublicKeyInfo is in tbsCertificate (first element), at index 6
    const tbsCert = cert.root.subs[0];
    const spki = tbsCert.subs[6];
    const algorithmSeq = spki.subs[0];

    const algorithm = algorithmSeq.subs[0].toOID();
    const curve = algorithmSeq.subs[1]?.toOID() || '';

    return { algorithm, curve };
  }

  private decodeExtensionInteger(value: Uint8Array): number {
    // Extension value is wrapped in OCTET STRING, parse the inner DER INTEGER
    const asn1 = ASN1Obj.parseBuffer(value);
    return Number(asn1.toInteger());
  }

  get vcekPublicKey(): Promise<CryptoKey> {
    return this.vcek.publicKeyObj;
  }
}

async function fetchAndCacheVCEK(vcekUrl: string): Promise<Uint8Array> {
  const vcekDer = await fetchVCEK(vcekUrl);

  // Cache for future use (URL serves as cache key)
  if (typeof localStorage !== 'undefined') {
    try {
      const base64 = btoa(String.fromCharCode(...vcekDer));
      localStorage.setItem(vcekUrl, base64);
    } catch {
      // Cache storage failed (quota exceeded, etc), continue anyway
    }
  }

  return vcekDer;
}

export function buildVCEKUrl(productName: string, chipId: Uint8Array, reportedTcb: bigint): string {
  const tcb = tcbFromInt(reportedTcb);
  const chipIdHex = bytesToHex(chipId);
  const baseUrl = 'https://kds-proxy.tinfoil.sh/vcek/v1';

  return `${baseUrl}/${productName}/${chipIdHex}?blSPL=${tcb.blSpl}&teeSPL=${tcb.teeSpl}&snpSPL=${tcb.snpSpl}&ucodeSPL=${tcb.ucodeSpl}`;
}

export async function fetchVCEK(url: string): Promise<Uint8Array> {
  const response = await fetch(url);

  if (!response.ok) {
    throw new FetchError(`Failed to fetch VCEK certificate from AMD KDS: HTTP ${response.status} ${response.statusText}`);
  }

  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}
