export enum PredicateType {
  SevGuestV1 = 'https://tinfoil.sh/predicate/sev-snp-guest/v1', // Deprecated
  SevGuestV2 = 'https://tinfoil.sh/predicate/sev-snp-guest/v2',
  SnpTdxMultiplatformV1 = 'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1',
}

export interface AttestationDocument {
  format: PredicateType;
  body: string;
}

/**
 * Complete attestation bundle from single-request verification.
 */
export interface AttestationBundle {
  /** Selected enclave domain hostname */
  domain: string;
  /** Enclave attestation report (from router's /.well-known/tinfoil-attestation) */
  enclaveAttestationReport: AttestationDocument;
  /** SHA256 digest of the release */
  digest: string;
  /** Sigstore bundle for code provenance verification */
  sigstoreBundle: unknown;
  /** Base64-encoded VCEK certificate (DER format) */
  vcek: string;
  /** PEM-encoded enclave TLS certificate (contains HPKE key and attestation hash in SANs) */
  enclaveCert: string;
}

export interface AttestationMeasurement {
  type: string;
  registers: string[];
}

export interface AttestationResponse {
  tlsPublicKeyFingerprint?: string;
  hpkePublicKey?: string;
  measurement: AttestationMeasurement;
}

import { ValidationError } from './errors.js';

/**
 * Compares two measurements for equality.
 * Handles cross-platform comparison between SnpTdxMultiplatformV1 and SevGuestV2.
 * @throws ValidationError if the measurement types are incompatible or registers don't match
 */
export function compareMeasurements(a: AttestationMeasurement, b: AttestationMeasurement): void {
  // Exact type match - compare all registers
  if (a.type === b.type) {
    if (a.registers.length !== b.registers.length ||
        !a.registers.every((reg, i) => reg === b.registers[i])) {
      throw new ValidationError('Measurement mismatch: registers do not match');
    }
    return;
  }

  // Cross-platform: SnpTdxMultiplatformV1 vs SevGuestV2
  // MultiPlatform registers: [snp, rtmr1, rtmr2]
  // SevGuestV2 registers: [snp]
  // Only compare the SNP measurement (first register of both)
  if (a.type === PredicateType.SnpTdxMultiplatformV1 && b.type === PredicateType.SevGuestV2) {
    if (a.registers.length < 1 || b.registers.length < 1) {
      throw new ValidationError('Insufficient registers for comparison');
    }
    if (a.registers[0] !== b.registers[0]) {
      throw new ValidationError('SNP measurement mismatch');
    }
    return;
  }

  // Reverse direction
  if (a.type === PredicateType.SevGuestV2 && b.type === PredicateType.SnpTdxMultiplatformV1) {
    if (a.registers.length < 1 || b.registers.length < 1) {
      throw new ValidationError('Insufficient registers for comparison');
    }
    if (a.registers[0] !== b.registers[0]) {
      throw new ValidationError('SNP measurement mismatch');
    }
    return;
  }

  throw new ValidationError(
    `Measurement types are incompatible: '${a.type}' vs '${b.type}'`
  );
}

/**
 * Computes the fingerprint of a measurement.
 * If there is only one register, returns that register directly.
 * Otherwise, returns SHA-256 hash of type + all registers concatenated.
 */
export async function measurementFingerprint(m: AttestationMeasurement): Promise<string> {
  if (m.registers.length === 1) {
    return m.registers[0];
  }

  const allData = m.type + m.registers.join('');
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(allData));
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Computes the SHA-256 hash of an attestation document.
 * This matches the Go implementation: sha256(format + body)
 */
export async function hashAttestationDocument(doc: AttestationDocument): Promise<string> {
  const data = doc.format + doc.body;
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
}

export interface VerificationStepState {
  status: 'pending' | 'success' | 'failed';
  error?: string;
}

export interface HardwareMeasurement {
  ID?: string;
  MRTD?: string;
  RTMR0?: string;
}

export interface VerificationDocument {
  configRepo: string;
  enclaveHost: string;
  releaseDigest: string;
  codeMeasurement: AttestationMeasurement;
  enclaveMeasurement: AttestationResponse;
  tlsPublicKey: string;
  hpkePublicKey: string;
  hardwareMeasurement?: HardwareMeasurement;
  codeFingerprint: string;
  enclaveFingerprint: string;
  selectedRouterEndpoint: string;
  securityVerified: boolean;
  steps: {
    fetchDigest: VerificationStepState;
    verifyCode: VerificationStepState;
    verifyEnclave: VerificationStepState;
    compareMeasurements: VerificationStepState;
    verifyCertificate?: VerificationStepState;
    createTransport?: VerificationStepState;
    verifyHPKEKey?: VerificationStepState;
    otherError?: VerificationStepState;
  };
}

