/**
 * verify-hardware-measurements (SPEC §6) — TDX hardware platform matching.
 *
 * @tinfoilsh/verifier exposes the HardwareMeasurement interface but no
 * dedicated matching function — the §6.3 algorithm is just a list scan and
 * users typically inline it at the application layer. The conformance binary
 * implements §6.3 here so the SPEC behavior is testable cross-SDK; if/when a
 * lib helper lands, swap this in.
 */

const TDX_URI = 'https://tinfoil.sh/predicate/tdx-guest/v2';
const TDX_REGISTER_COUNT = 5;

interface MeasurementInput {
  type: string;
  registers: string[];
}

interface HardwareMeasurementInput {
  id: string;
  mrtd: string;
  rtmr0: string;
}

interface VerifyHardwareInput {
  schema_version?: string;
  enclave_measurement?: MeasurementInput;
  hardware_measurements?: HardwareMeasurementInput[];
}

function rejection(code: string, spec_ref: string, message: string) {
  return {
    exitCode: 10,
    body: {
      stage: 'verify-hardware-measurements',
      accepted: false,
      rejection: { code, spec_ref, message },
    },
  };
}

export async function verifyHardwareMeasurements(
  parsed: unknown,
): Promise<{ exitCode: number; body: unknown }> {
  const inp = parsed as VerifyHardwareInput;
  if (!inp || inp.schema_version !== '1') {
    return {
      exitCode: 30,
      body: {
        stage: 'verify-hardware-measurements',
        accepted: false,
        rejection: {
          code: 'HARDWARE_NO_MATCH',
          spec_ref: '6',
          message: 'schema_version must be "1"',
        },
      },
    };
  }

  const enclave = inp.enclave_measurement;
  if (!enclave) {
    return rejection('ENCLAVE_MEASUREMENT_TYPE_INVALID', '6.3', 'missing enclave_measurement');
  }
  // SPEC §6.3 step 1: enclave_measurement MUST be TdxGuestV2 with exactly 5
  // registers.
  if (enclave.type !== TDX_URI) {
    return rejection(
      'ENCLAVE_MEASUREMENT_TYPE_INVALID',
      '6.3',
      'enclave measurement type is not TdxGuestV2',
    );
  }
  if (!Array.isArray(enclave.registers) || enclave.registers.length !== TDX_REGISTER_COUNT) {
    return rejection(
      'ENCLAVE_REGISTER_COUNT_INVALID',
      '6.3',
      `TDX enclave measurement must have ${TDX_REGISTER_COUNT} registers, got ${enclave.registers?.length ?? 0}`,
    );
  }

  // SPEC §7.3 lowercase normalization.
  const enclaveMrtd = enclave.registers[0].toLowerCase();
  const enclaveRtmr0 = enclave.registers[1].toLowerCase();
  const hwList = inp.hardware_measurements ?? [];

  // SPEC §6.3 step 3: return the FIRST matching hardware measurement.
  for (const hw of hwList) {
    const hwMrtd = hw.mrtd.toLowerCase();
    const hwRtmr0 = hw.rtmr0.toLowerCase();
    if (hwMrtd === enclaveMrtd && hwRtmr0 === enclaveRtmr0) {
      return {
        exitCode: 0,
        body: {
          stage: 'verify-hardware-measurements',
          accepted: true,
          outputs: {
            matched_id: hw.id,
            matched_mrtd: hwMrtd,
            matched_rtmr0: hwRtmr0,
          },
        },
      };
    }
  }
  return rejection('HARDWARE_NO_MATCH', '6.3', 'no matching hardware platform found');
}
