import type { Report } from './report.js';
import type { TCBParts } from './types.js';
import { ReportSigner } from './constants.js';
import { ARK_CERT, ASK_CERT } from './certs.js';
import { tcbFromInt, bytesToHex } from './utils.js';
import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { ASN1Obj, uint8ArrayEqual } from '@freedomofpress/crypto-browser';
import { FetchError, VerificationError } from '../errors.js';

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
      throw new VerificationError('This implementation only supports Genoa processors');
    }

    if (report.signerInfoParsed.signingKey !== ReportSigner.VcekReportSigner) {
      throw new VerificationError('This implementation only supports VCEK signed reports');
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
        throw new VerificationError('ARK certificate is not valid for current date');
      }
      if (!this.ask.validForDate(now)) {
        throw new VerificationError('ASK certificate is not valid for current date');
      }
      if (!this.vcek.validForDate(now)) {
        throw new VerificationError('VCEK certificate is not valid for current date');
      }

      // Verify signature chain: ARK self-signed, ARK signs ASK, ASK signs VCEK
      const arkSelfSigned = await this.ark.verify();
      if (!arkSelfSigned) {
        throw new VerificationError('ARK certificate is not self-signed');
      }

      const askSignedByArk = await this.ask.verify(this.ark);
      if (!askSignedByArk) {
        throw new VerificationError('ASK certificate is not signed by ARK');
      }

      const vcekSignedByAsk = await this.vcek.verify(this.ask);
      if (!vcekSignedByAsk) {
        throw new VerificationError('VCEK certificate is not signed by ASK');
      }

      return true;
    } catch (e) {
      throw new VerificationError('Certificate chain verification failed', { cause: e as Error });
    }
  }

  validateVcekTcb(tcb: TCBParts): void {
    // Validate BL_SPL
    const blSplExt = this.vcek.extension(SnpOid.BL_SPL);
    if (!blSplExt) {
      throw new VerificationError('missing BL_SPL extension for VCEK certificate');
    }
    const blSpl = this.decodeExtensionInteger(blSplExt.value);
    if (blSpl !== tcb.blSpl) {
      throw new VerificationError(`BL_SPL extension in VCEK certificate does not match tcb.blSpl: ${blSpl} != ${tcb.blSpl}`);
    }

    // Validate TEE_SPL
    const teeSplExt = this.vcek.extension(SnpOid.TEE_SPL);
    if (!teeSplExt) {
      throw new VerificationError('missing TEE_SPL extension for VCEK certificate');
    }
    const teeSpl = this.decodeExtensionInteger(teeSplExt.value);
    if (teeSpl !== tcb.teeSpl) {
      throw new VerificationError(`TEE_SPL extension in VCEK certificate does not match tcb.teeSpl: ${teeSpl} != ${tcb.teeSpl}`);
    }

    // Validate SNP_SPL
    const snpSplExt = this.vcek.extension(SnpOid.SNP_SPL);
    if (!snpSplExt) {
      throw new VerificationError('missing SNP_SPL extension for VCEK certificate');
    }
    const snpSpl = this.decodeExtensionInteger(snpSplExt.value);
    if (snpSpl !== tcb.snpSpl) {
      throw new VerificationError(`SNP_SPL extension in VCEK certificate does not match tcb.snpSpl: ${snpSpl} != ${tcb.snpSpl}`);
    }

    // Validate UCODE
    const ucodeExt = this.vcek.extension(SnpOid.UCODE);
    if (!ucodeExt) {
      throw new VerificationError('missing UCODE extension for VCEK certificate');
    }
    const ucodeSpl = this.decodeExtensionInteger(ucodeExt.value);
    if (ucodeSpl !== tcb.ucodeSpl) {
      throw new VerificationError(`UCODE extension in VCEK certificate does not match tcb.ucodeSpl: ${ucodeSpl} != ${tcb.ucodeSpl}`);
    }
  }

  validateVcekHwid(chipId: Uint8Array): void {
    const hwidExt = this.vcek.extension(SnpOid.HWID);
    if (!hwidExt) {
      throw new VerificationError('missing HWID extension for VCEK certificate');
    }

    // The HWID extension value is the raw chip ID bytes
    if (!uint8ArrayEqual(hwidExt.value, chipId)) {
      throw new VerificationError(`HWID extension in VCEK certificate does not match chip_id: ${bytesToHex(hwidExt.value)} != ${bytesToHex(chipId)}`);
    }
  }

  private validateArkFormat(): void {
    // Validate certificate version (must be v3)
    if (this.ark.version !== 'v3') {
      throw new VerificationError(`ARK certificate version is not v3 but ${this.ark.version}`);
    }

    // Validate AMD location for issuer and subject
    if (!this.validateAmdLocation(this.ark.issuerDN)) {
      throw new VerificationError('ARK certificate issuer is not a valid AMD location');
    }
    if (!this.validateAmdLocation(this.ark.subjectDN)) {
      throw new VerificationError('ARK certificate subject is not a valid AMD location');
    }

    // Check common name
    const cn = this.ark.subjectDN.get('CN');
    if (cn !== 'ARK-Genoa') {
      throw new VerificationError(`ARK certificate subject common name is not ARK-Genoa but ${cn}`);
    }
  }

  private validateAskFormat(): void {
    // Validate certificate version (must be v3)
    if (this.ask.version !== 'v3') {
      throw new VerificationError(`ASK certificate version is not v3 but ${this.ask.version}`);
    }

    // Validate AMD location
    if (!this.validateAmdLocation(this.ask.issuerDN)) {
      throw new VerificationError('ASK certificate issuer is not a valid AMD location');
    }
    if (!this.validateAmdLocation(this.ask.subjectDN)) {
      throw new VerificationError('ASK certificate subject is not a valid AMD location');
    }

    // Check common name is exactly "SEV-Genoa" (ASK cert uses SEV-Genoa)
    const cn = this.ask.subjectDN.get('CN');
    if (cn !== 'SEV-Genoa') {
      throw new VerificationError(`ASK certificate subject common name is not SEV-Genoa but ${cn}`);
    }
  }

  private validateVcekFormat(): void {
    // Validate certificate version (must be v3)
    if (this.vcek.version !== 'v3') {
      throw new VerificationError(`VCEK certificate version is not v3 but ${this.vcek.version}`);
    }

    // Validate AMD location
    if (!this.validateAmdLocation(this.vcek.issuerDN)) {
      throw new VerificationError('VCEK certificate issuer is not a valid AMD location');
    }
    if (!this.validateAmdLocation(this.vcek.subjectDN)) {
      throw new VerificationError('VCEK certificate subject is not a valid AMD location');
    }

    // Validate common name
    const cn = this.vcek.subjectDN.get('CN');
    if (cn !== 'SEV-VCEK') {
      throw new VerificationError(`VCEK certificate subject common name is not SEV-VCEK but ${cn}`);
    }

    // Validate signature algorithm (must be RSASSA-PSS for VCEK signed by ASK)
    const sigAlgOid = this.getSignatureAlgorithmOid(this.vcek);
    if (sigAlgOid !== OID_RSASSA_PSS) {
      throw new VerificationError(`VCEK certificate signature algorithm is not RSASSA-PSS but ${sigAlgOid}`);
    }

    // Validate public key algorithm and curve
    const { algorithm, curve } = this.getPublicKeyInfo(this.vcek);
    if (algorithm !== OID_EC_PUBLIC_KEY) {
      throw new VerificationError(`VCEK certificate public key algorithm is not ECDSA but ${algorithm}`);
    }
    if (curve !== OID_SECP384R1) {
      throw new VerificationError(`VCEK certificate public key curve is not secp384r1 but ${curve}`);
    }

    // CSP_ID must NOT be present (critical for VCEK vs VLEK distinction)
    const cspIdExt = this.vcek.extension(SnpOid.CSP_ID);
    if (cspIdExt) {
      throw new VerificationError(`unexpected CSP_ID in VCEK certificate: ${bytesToHex(cspIdExt.value)}`);
    }

    // HWID must be present and correct length
    const hwidExt = this.vcek.extension(SnpOid.HWID);
    if (!hwidExt || hwidExt.value.length !== 64) {
      throw new VerificationError('missing or invalid HWID extension for VCEK certificate');
    }

    // Product name validation
    const productNameExt = this.vcek.extension(SnpOid.PRODUCT_NAME);
    if (!productNameExt) {
      throw new VerificationError('missing PRODUCT_NAME extension for VCEK certificate');
    }
    // The extension value should be DER-encoded IA5String: tag 0x16, length 0x05, value "Genoa"
    const expectedProductName = new Uint8Array([0x16, 0x05, 0x47, 0x65, 0x6e, 0x6f, 0x61]);
    if (!uint8ArrayEqual(productNameExt.value, expectedProductName)) {
      throw new VerificationError(`unexpected PRODUCT_NAME in VCEK certificate: ${bytesToHex(productNameExt.value)}`);
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

function buildVCEKUrl(productName: string, chipId: Uint8Array, reportedTcb: bigint): string {
  const tcb = tcbFromInt(reportedTcb);
  const chipIdHex = bytesToHex(chipId);
  const baseUrl = 'https://kds-proxy.tinfoil.sh/vcek/v1';

  return `${baseUrl}/${productName}/${chipIdHex}?blSPL=${tcb.blSpl}&teeSPL=${tcb.teeSpl}&snpSPL=${tcb.snpSpl}&ucodeSPL=${tcb.ucodeSpl}`;
}

async function fetchVCEK(url: string): Promise<Uint8Array> {
  const response = await fetch(url);

  if (!response.ok) {
    throw new FetchError(`Failed to fetch VCEK certificate: ${response.status} ${response.statusText}`);
  }

  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}
