import { ConfigurationError } from './errors.js';
import { PredicateType } from './types.js';
import type { AttestationMeasurement } from './types.js';

/** Workload pin for this verifier's supported SEV-SNP platform. */
export interface CodeMeasurement {
  snp_measurement: string;
}

/** Register values are 48-byte digests, so a well-formed register is 96 hex characters. */
const REGISTER_HEX_LENGTH = 96;
const HEX_PATTERN = /^[0-9a-f]+$/i;

/** Validates and snapshots the release's SNP measurement into the verifier's register layout. */
export function validatePinnedMeasurement(measurement: unknown): AttestationMeasurement {
  if (measurement === null || typeof measurement !== 'object') {
    throw new ConfigurationError('pinnedMeasurement must be an object with snp_measurement');
  }
  if ('tdx_measurement' in measurement) {
    throw new ConfigurationError('pinnedMeasurement: this verifier does not support TDX');
  }
  const register = (measurement as { snp_measurement?: unknown }).snp_measurement;
  if (typeof register !== 'string' || register.length !== REGISTER_HEX_LENGTH || !HEX_PATTERN.test(register)) {
    throw new ConfigurationError(`pinnedMeasurement.snp_measurement must be ${REGISTER_HEX_LENGTH} hex characters`);
  }
  return { type: PredicateType.SevGuestV2, registers: [register.toLowerCase()] };
}
