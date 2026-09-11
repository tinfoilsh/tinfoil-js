import { ConfigurationError } from './errors.js';
import { PredicateType } from './types.js';
import type { AttestationMeasurement } from './types.js';

/** Register values are 48-byte digests, so a well-formed register is 96 hex characters. */
const REGISTER_HEX_LENGTH = 96;
const HEX_PATTERN = /^[0-9a-f]+$/;

/**
 * Register layout each supported code measurement type must carry. This
 * verifier only verifies SEV-SNP attestation, so TDX runtime measurements are
 * not accepted as pins.
 */
const REGISTER_COUNTS: Record<string, number> = {
  [PredicateType.SevGuestV2]: 1,
  [PredicateType.SnpTdxMultiplatformV1]: 3,
};

/**
 * Validates a caller-supplied code measurement and returns an independent,
 * lowercase-normalized copy so the caller's value cannot change what
 * verification later accepts.
 *
 * @throws ConfigurationError when the measurement is missing, has an
 *   unsupported type, the wrong register count for its type, or a register
 *   that is not 48-byte hex.
 */
export function validatePinnedMeasurement(measurement: unknown): AttestationMeasurement {
  if (measurement === null || typeof measurement !== 'object') {
    throw new ConfigurationError('pinnedMeasurement must be an object with a type and registers');
  }
  const { type, registers } = measurement as { type?: unknown; registers?: unknown };
  if (typeof type !== 'string' || type === '') {
    throw new ConfigurationError('pinnedMeasurement must include a type');
  }
  const expectedCount = REGISTER_COUNTS[type];
  if (expectedCount === undefined) {
    throw new ConfigurationError(`pinnedMeasurement has unsupported type "${type}"`);
  }
  if (!Array.isArray(registers)) {
    throw new ConfigurationError('pinnedMeasurement.registers must be an array');
  }
  if (registers.length !== expectedCount) {
    throw new ConfigurationError(
      `pinnedMeasurement of type "${type}" must have ${expectedCount} register(s), got ${registers.length}`
    );
  }

  const normalized = registers.map((register, index) => {
    if (typeof register !== 'string') {
      throw new ConfigurationError(`pinnedMeasurement.registers[${index}] must be a string`);
    }
    const lowered = register.toLowerCase();
    if (lowered.length !== REGISTER_HEX_LENGTH || !HEX_PATTERN.test(lowered)) {
      throw new ConfigurationError(
        `pinnedMeasurement.registers[${index}] must be ${REGISTER_HEX_LENGTH} hex characters`
      );
    }
    return lowered;
  });

  return { type, registers: normalized };
}
