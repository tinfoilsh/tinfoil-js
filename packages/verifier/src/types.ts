export enum PredicateType {
  SevGuestV1 = 'https://tinfoil.sh/predicate/sev-snp-guest/v1', // Deprecated
  SevGuestV2 = 'https://tinfoil.sh/predicate/sev-snp-guest/v2',
  TdxGuestV2 = 'https://tinfoil.sh/predicate/tdx-guest/v2',
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

import { AttestationError } from './errors.js';
import { RTMR3_ZERO } from './tdx/constants.js';

/**
 * Compares two measurements for equality.
 * Handles cross-platform comparisons:
 *   - SnpTdxMultiplatformV1 vs SevGuestV2 (SNP measurement)
 *   - SnpTdxMultiplatformV1 vs TdxGuestV2 (RTMR1, RTMR2 + RTMR3 zero check)
 * @throws AttestationError if the measurement types are incompatible or registers don't match
 */
export function compareMeasurements(a: AttestationMeasurement, b: AttestationMeasurement): void {
  // Exact type match - compare all registers
  if (a.type === b.type) {
    if (a.registers.length !== b.registers.length ||
        !a.registers.every((reg, i) => reg === b.registers[i])) {
      throw new AttestationError('Code measurement mismatch: The enclave is running different code than the expected release');
    }
    return;
  }

  // Cross-platform: SnpTdxMultiplatformV1 vs SevGuestV2
  // MultiPlatform registers: [snp, rtmr1, rtmr2]
  // SevGuestV2 registers: [snp]
  if (a.type === PredicateType.SnpTdxMultiplatformV1 && b.type === PredicateType.SevGuestV2) {
    compareMultiplatformVsSev(a, b);
    return;
  }
  if (a.type === PredicateType.SevGuestV2 && b.type === PredicateType.SnpTdxMultiplatformV1) {
    compareMultiplatformVsSev(b, a);
    return;
  }

  // Cross-platform: SnpTdxMultiplatformV1 vs TdxGuestV2
  // MultiPlatform registers: [snp, rtmr1, rtmr2]
  // TdxGuestV2 registers: [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
  if (a.type === PredicateType.SnpTdxMultiplatformV1 && b.type === PredicateType.TdxGuestV2) {
    compareMultiplatformVsTdx(a, b);
    return;
  }
  if (a.type === PredicateType.TdxGuestV2 && b.type === PredicateType.SnpTdxMultiplatformV1) {
    compareMultiplatformVsTdx(b, a);
    return;
  }

  throw new AttestationError(
    `Cannot compare measurements: Incompatible measurement types "${a.type}" and "${b.type}"`
  );
}

function compareMultiplatformVsSev(
  multi: AttestationMeasurement,
  sev: AttestationMeasurement,
): void {
  if (multi.registers.length < 1 || sev.registers.length < 1) {
    throw new AttestationError('Invalid measurement data: Missing measurement registers');
  }
  if (multi.registers[0] !== sev.registers[0]) {
    throw new AttestationError(
      'Code measurement mismatch: The SNP measurement from the enclave does not match the expected measurement from the signed release'
    );
  }
}

function compareMultiplatformVsTdx(
  multi: AttestationMeasurement,
  tdx: AttestationMeasurement,
): void {
  if (multi.registers.length < 3) {
    throw new AttestationError(
      'Invalid measurement data: MultiPlatform measurement must have at least 3 registers'
    );
  }
  if (tdx.registers.length < 5) {
    throw new AttestationError(
      'Invalid measurement data: TDX measurement must have exactly 5 registers'
    );
  }

  // MultiPlatform[1] (RTMR1) must equal TDX[2] (RTMR1)
  if (multi.registers[1] !== tdx.registers[2]) {
    throw new AttestationError(
      'Code measurement mismatch: RTMR1 from the enclave does not match the expected measurement from the signed release'
    );
  }

  // MultiPlatform[2] (RTMR2) must equal TDX[3] (RTMR2)
  if (multi.registers[2] !== tdx.registers[3]) {
    throw new AttestationError(
      'Code measurement mismatch: RTMR2 from the enclave does not match the expected measurement from the signed release'
    );
  }

  // TDX[4] (RTMR3) must be all zeros
  if (tdx.registers[4] !== RTMR3_ZERO) {
    throw new AttestationError(
      'Code measurement mismatch: RTMR3 must be all zeros'
    );
  }
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
    otherError?: VerificationStepState;
  };
}

