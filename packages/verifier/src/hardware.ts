import { PredicateType } from './types.js';
import type { AttestationMeasurement, HardwareMeasurement } from './types.js';
import { AttestationError } from './errors.js';

export function verifyHardware(
  measurements: HardwareMeasurement[],
  enclaveMeasurement: AttestationMeasurement | null | undefined,
): HardwareMeasurement {
  if (!enclaveMeasurement) {
    throw new AttestationError('enclave measurement is nil');
  }

  if (enclaveMeasurement.type !== PredicateType.TdxGuestV2) {
    throw new AttestationError(`unsupported enclave platform: ${enclaveMeasurement.type}`);
  }

  if (enclaveMeasurement.registers.length < 2) {
    throw new AttestationError(
      `enclave provided fewer registers than expected: ${enclaveMeasurement.registers.length}`,
    );
  }

  for (const measurement of measurements) {
    if (measurement.MRTD === enclaveMeasurement.registers[0] &&
        measurement.RTMR0 === enclaveMeasurement.registers[1]) {
      return measurement;
    }
  }

  throw new AttestationError('no matching hardware platform found');
}
