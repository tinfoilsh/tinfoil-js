import type { AttestationDocument, AttestationResponse } from './types.js';
import { PredicateType } from './types.js';
import { Report } from './sev/report.js';
import { CertificateChain } from './sev/cert-chain.js';
import { verifyAttestation as verifyAttestationInternal } from './sev/verify.js';
import { bytesToHex } from './sev/utils.js';
import { validateReport, defaultValidationOptions } from './sev/validation.js';

const ATTESTATION_ENDPOINT = '/.well-known/tinfoil-attestation';

/**
 * Retrieves the attestation document from a given enclave hostname.
 *
 * @param host - The hostname of the enclave
 * @returns The attestation document
 * @throws Error if the request fails
 */
export async function fetchAttestation(host: string): Promise<AttestationDocument> {
  const url = `https://${host}${ATTESTATION_ENDPOINT}`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch attestation: ${response.status} ${response.statusText}`);
  }

  const docDict = await response.json();

  return {
    format: docDict.format as PredicateType,
    body: docDict.body,
  };
}

/**
 * Checks the attestation document against its trust root
 * and returns the inner measurements.
 *
 * @param doc - The attestation document to verify
 * @param vcekBase64 - Optional pre-fetched VCEK certificate in base64-encoded DER format
 * @returns The verification result
 * @throws Error if verification fails or format is unsupported
 */
export async function verifyAttestation(doc: AttestationDocument, vcekBase64?: string): Promise<AttestationResponse> {
  if (doc.format === PredicateType.SevGuestV2) {
    const vcekDer = vcekBase64 ? base64ToBytes(vcekBase64) : undefined;
    return verifySevAttestationV2(doc.body, vcekDer);
  } else {
    throw new Error(`Unsupported attestation format: ${doc.format}`);
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
async function verifySevAttestationV2(attestationDoc: string, vcekDer?: Uint8Array): Promise<AttestationResponse> {
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
async function verifySevReport(attestationDoc: string, isCompressed: boolean, vcekDer?: Uint8Array): Promise<Report> {
  let attDocBytes: Uint8Array;
  try {
    attDocBytes = base64ToBytes(attestationDoc);
  } catch (e) {
    throw new Error('Failed to decode base64', { cause: e });
  }

  if (isCompressed) {
    attDocBytes = await decompressGzip(attDocBytes);
  }

  let report: Report;
  try {
    report = new Report(attDocBytes);
  } catch (e) {
    throw new Error('Failed to parse report', { cause: e });
  }

  const chain = await CertificateChain.fromReport(report, vcekDer);

  let res: boolean;
  try {
    res = await verifyAttestationInternal(chain, report);
  } catch (e) {
    throw new Error('Failed to verify attestation', { cause: e });
  }

  if (!res) {
    throw new Error('Attestation verification failed!');
  }

  try {
    validateReport(report, chain, defaultValidationOptions);
  } catch (e) {
    throw new Error('Failed to validate report', { cause: e });
  }

  return report;
}

function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

async function decompressGzip(data: Uint8Array): Promise<Uint8Array> {
  // Use DecompressionStream if available (browsers, Node.js 18+)
  if (typeof DecompressionStream !== 'undefined') {
    const stream = new Response(data.buffer as ArrayBuffer).body;
    if (!stream) {
      throw new Error('Failed to create stream from data');
    }

    const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
    const decompressed = await new Response(decompressedStream).arrayBuffer();
    return new Uint8Array(decompressed);
  }

  // Fallback to Node.js/Bun zlib
  const { gunzipSync } = await import('zlib');
  return new Uint8Array(gunzipSync(data));
}
