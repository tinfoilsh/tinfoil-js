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

export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AttestationError';
  }
}

export class FormatMismatchError extends AttestationError {
  constructor(message: string = 'Attestation formats do not match') {
    super(message);
    this.name = 'FormatMismatchError';
  }
}

export class MeasurementMismatchError extends AttestationError {
  constructor(message: string = 'Measurements do not match') {
    super(message);
    this.name = 'MeasurementMismatchError';
  }
}

/**
 * Check if a predicate type is SNP-compatible (contains SNP measurements)
 */
function isSnpCompatible(type: string): boolean {
  return type === PredicateType.SevGuestV1 ||
         type === PredicateType.SevGuestV2 ||
         type === PredicateType.SnpTdxMultiplatformV1;
}

/**
 * Compares two measurements for equality.
 * @throws FormatMismatchError if the measurement types are incompatible
 * @throws MeasurementMismatchError if the registers don't match
 */
export function compareMeasurements(a: AttestationMeasurement, b: AttestationMeasurement): void {
  // Allow comparison between compatible SNP types
  const typesCompatible = a.type === b.type || (isSnpCompatible(a.type) && isSnpCompatible(b.type));
  if (!typesCompatible) {
    throw new FormatMismatchError(
      `Measurement types are incompatible: '${a.type}' vs '${b.type}'`
    );
  }
  if (a.registers.length !== b.registers.length ||
      !a.registers.every((reg, i) => reg === b.registers[i])) {
    throw new MeasurementMismatchError(
      `Measurement registers do not match`
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
    createTransport?: VerificationStepState;
    verifyHPKEKey?: VerificationStepState;
    otherError?: VerificationStepState;
  };
}

