import type { AttestationDocument, AttestationResponse } from './types.js';
import { PredicateType } from './types.js';
import { Report } from './sev/report.js';
import { CertificateChain } from './sev/cert-chain.js';
import { verifyAttestation as verifyAttestationInternal } from './sev/verify.js';
import { bytesToHex } from './sev/utils.js';
import { validateReport, defaultValidationOptions } from './sev/validation.js';
import { parseTdxQuote } from './tdx/quote.js';
import { PckCertificateChain } from './tdx/cert-chain.js';
import { verifyQuoteSignature, verifyQeReportSignature, verifyQeReportDataBinding } from './tdx/verify.js';
import { validateTdxQuote, defaultTdxValidationOptions } from './tdx/validation.js';
import { parsePckExtensions } from './tdx/pck-extensions.js';
import { validateCollateral } from './tdx/collateral.js';
import { AttestationError, wrapOrThrow } from './errors.js';

/**
 * Checks the attestation document against its trust root
 * and returns the inner measurements.
 *
 * @param doc - The attestation document to verify
 * @param vcekBase64 - VCEK certificate in base64-encoded DER format (required for SEV, ignored for TDX)
 * @returns The verification result
 * @throws Error if verification fails or format is unsupported
 */
export async function verifyAttestation(doc: AttestationDocument, vcekBase64: string): Promise<AttestationResponse> {
  if (doc.format === PredicateType.SevGuestV2) {
    return verifySevAttestationV2(doc.body, base64ToBytes(vcekBase64));
  } else if (doc.format === PredicateType.TdxGuestV2) {
    return verifyTdxAttestationV2(doc.body);
  } else {
    throw new AttestationError(`Unsupported attestation document format: "${doc.format}". Supported formats: SEV-SNP Guest V2, TDX Guest V2`);
  }
}

/**
 * Verify SEV attestation document and return verification result.
 *
 * @param attestationDoc - Base64 encoded attestation document
 * @param vcekDer - Optional pre-fetched VCEK certificate in DER format
 * @returns Verification result
 * @throws Error if verification fails
 */
async function verifySevAttestationV2(attestationDoc: string, vcekDer: Uint8Array): Promise<AttestationResponse> {
  const report = await verifySevReport(attestationDoc, true, vcekDer);

  const measurement = {
    type: PredicateType.SevGuestV2,
    registers: [bytesToHex(report.measurement)],
  };

  const keys = report.reportData;
  const tlsKeyFp = bytesToHex(keys.slice(0, 32));
  const hpkePublicKey = bytesToHex(keys.slice(32, 64));

  return {
    measurement,
    tlsPublicKeyFingerprint: tlsKeyFp,
    hpkePublicKey,
  };
}

/**
 * Verify SEV attestation document and return verification result.
 *
 * @param attestationDoc - Base64 encoded attestation document
 * @param isCompressed - Whether the document is gzip compressed
 * @param vcekDer - Optional pre-fetched VCEK certificate in DER format
 * @returns The parsed and verified report
 * @throws Error if verification fails
 */
async function verifySevReport(attestationDoc: string, isCompressed: boolean, vcekDer: Uint8Array): Promise<Report> {
  let attDocBytes: Uint8Array;
  try {
    attDocBytes = base64ToBytes(attestationDoc);
  } catch (e) {
    throw new AttestationError('Failed to decode attestation document: Invalid base64 encoding', { cause: e as Error });
  }

  if (isCompressed) {
    attDocBytes = await decompressGzip(attDocBytes);
  }

  let report: Report;
  try {
    report = new Report(attDocBytes);
  } catch (e) {
    throw new AttestationError('Failed to parse SEV-SNP attestation report', { cause: e as Error });
  }

  const chain = await CertificateChain.fromReport(report, vcekDer);

  let res: boolean;
  try {
    res = await verifyAttestationInternal(chain, report);
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Attestation cryptographic verification failed');
  }

  if (!res) {
    throw new AttestationError('Attestation verification failed: Report signature or certificate chain is invalid');
  }

  try {
    validateReport(report, chain, defaultValidationOptions);
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Attestation policy validation failed');
  }

  return report;
}

async function verifyTdxAttestationV2(attestationDoc: string): Promise<AttestationResponse> {
  let attDocBytes: Uint8Array;
  try {
    attDocBytes = base64ToBytes(attestationDoc);
  } catch (e) {
    throw new AttestationError('Failed to decode TDX attestation document: Invalid base64 encoding', { cause: e as Error });
  }

  attDocBytes = await decompressGzip(attDocBytes);

  let quote;
  try {
    quote = parseTdxQuote(attDocBytes);
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Failed to parse TDX quote');
  }

  // Verify PCK certificate chain against Intel SGX Root CA
  const chain = PckCertificateChain.fromPemChain(quote.pckCertChain);
  await chain.verifyChain();

  // Verify quote signature using attestation key
  await verifyQuoteSignature(quote);

  // Verify QE report signature using PCK certificate
  await verifyQeReportSignature(quote, chain);

  // Verify QE report data binding (attestation key endorsed by QE)
  await verifyQeReportDataBinding(quote);

  // Validate policy (TD attributes, XFAM, MR_SEAM, etc.)
  try {
    validateTdxQuote(quote, defaultTdxValidationOptions);
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'TDX policy validation failed');
  }

  // Parse PCK extensions and validate collateral (TCB Info, QE Identity, CRLs)
  const pckExtensions = parsePckExtensions(chain.pckLeaf);
  try {
    await validateCollateral(quote, chain, pckExtensions);
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'TDX collateral validation failed');
  }

  if (quote.body.rtmrs.length !== 4) {
    throw new AttestationError(`Expected 4 RTMRs, got ${quote.body.rtmrs.length}`);
  }

  const measurement = {
    type: PredicateType.TdxGuestV2 as string,
    registers: [
      bytesToHex(quote.body.mrTd),
      bytesToHex(quote.body.rtmrs[0]),
      bytesToHex(quote.body.rtmrs[1]),
      bytesToHex(quote.body.rtmrs[2]),
      bytesToHex(quote.body.rtmrs[3]),
    ],
  };

  const reportData = quote.body.reportData;
  const tlsKeyFp = bytesToHex(reportData.slice(0, 32));
  const hpkePublicKey = bytesToHex(reportData.slice(32, 64));

  return {
    measurement,
    tlsPublicKeyFingerprint: tlsKeyFp,
    hpkePublicKey,
  };
}

export function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

export async function decompressGzip(data: Uint8Array): Promise<Uint8Array> {
  // Use DecompressionStream if available (browsers, Node.js 18+)
  if (typeof DecompressionStream !== 'undefined') {
    const safeBuf = new Uint8Array(data).buffer as ArrayBuffer;
    const stream = new Response(safeBuf).body;
    if (!stream) {
      throw new Error('Failed to create stream from data');
    }

    const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
    const decompressed = await new Response(decompressedStream).arrayBuffer();
    return new Uint8Array(decompressed);
  }

  // Fallback to Node.js/Bun zlib (not available in browsers)
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { gunzipSync } = await import('zlib');
    return new Uint8Array(gunzipSync(data));
  }

  throw new Error('Gzip decompression is not supported in this environment: DecompressionStream is unavailable');
}
