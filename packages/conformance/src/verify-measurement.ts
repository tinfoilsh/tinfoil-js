/**
 * verify-measurement (SPEC §7) — cross-platform measurement fingerprinting
 * and comparison.
 *
 * Stateless / pure-function shim around `@tinfoilsh/verifier`'s
 * `measurementFingerprint` and `compareMeasurements` exports. The CLI input
 * lowercase-normalizes register values per SPEC §7.3 before invoking the lib,
 * so SDKs that don't normalize internally still pass the case-equivalence
 * fixture.
 */

import { compareMeasurements, measurementFingerprint } from '@tinfoilsh/verifier';
import type { AttestationMeasurement } from '@tinfoilsh/verifier';

interface MeasurementInput {
  type: string;
  registers: string[];
}

interface VerifyMeasurementInput {
  schema_version?: string;
  source?: MeasurementInput;
  target?: MeasurementInput | null;
}

const SEV_URI = 'https://tinfoil.sh/predicate/sev-snp-guest/v2';
const TDX_URI = 'https://tinfoil.sh/predicate/tdx-guest/v2';
const MP_URI = 'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1';

const EXPECTED_REGISTER_COUNT: Record<string, number> = {
  [SEV_URI]: 1,
  [TDX_URI]: 5,
  [MP_URI]: 3,
};

function isKnownType(t: string): boolean {
  return t in EXPECTED_REGISTER_COUNT;
}

function normalize(m: MeasurementInput):
  | { ok: true; measurement: AttestationMeasurement }
  | { ok: false; code: string; spec_ref: string } {
  if (!m || typeof m.type !== 'string' || !Array.isArray(m.registers)) {
    return { ok: false, code: 'MEASUREMENT_TYPE_UNKNOWN', spec_ref: '2.3' };
  }
  if (!isKnownType(m.type)) {
    return { ok: false, code: 'MEASUREMENT_TYPE_UNKNOWN', spec_ref: '2.3' };
  }
  if (m.registers.length !== EXPECTED_REGISTER_COUNT[m.type]) {
    return { ok: false, code: 'MEASUREMENT_REGISTER_COUNT_INVALID', spec_ref: '7.1' };
  }
  return {
    ok: true,
    measurement: {
      type: m.type,
      // SPEC §7.3: normalize register values to lowercase before any
      // comparison or storage.
      registers: m.registers.map((r) => r.toLowerCase()),
    },
  };
}

/**
 * Classify the lib's AttestationError message to a SPEC code.
 * sigstore/tinfoil-js's compareMeasurements throws AttestationError with
 * stable English phrasings — we map the recognized ones to SPEC codes.
 */
function classify(err: unknown, source: AttestationMeasurement, target: AttestationMeasurement): { code: string; spec_ref: string } {
  const msg = (err as Error).message || '';
  if (/rtmr3|rtmr_3/i.test(msg)) {
    return { code: 'MEASUREMENT_RTMR3_NONZERO', spec_ref: '7.3.2' };
  }
  if (/Incompatible measurement types/i.test(msg)) {
    return { code: 'MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED', spec_ref: '7.3.5' };
  }
  if (/Missing measurement registers/i.test(msg)) {
    return { code: 'MEASUREMENT_REGISTER_COUNT_INVALID', spec_ref: '7.1' };
  }
  if (/measurement mismatch/i.test(msg) || /SNP measurement/i.test(msg)) {
    return { code: 'MEASUREMENT_MISMATCH', spec_ref: '7.3' };
  }
  return { code: 'MEASUREMENT_MISMATCH', spec_ref: '7.3' };
}

export async function verifyMeasurement(
  parsed: unknown,
): Promise<{ exitCode: number; body: unknown }> {
  const inp = parsed as VerifyMeasurementInput;
  if (!inp || inp.schema_version !== '1') {
    return {
      exitCode: 30,
      body: {
        stage: 'verify-measurement',
        accepted: false,
        rejection: {
          code: 'MEASUREMENT_TYPE_UNKNOWN',
          spec_ref: '7',
          message: 'schema_version must be "1"',
        },
      },
    };
  }

  if (!inp.source) {
    return {
      exitCode: 10,
      body: {
        stage: 'verify-measurement',
        accepted: false,
        rejection: {
          code: 'MEASUREMENT_TYPE_UNKNOWN',
          spec_ref: '7',
          message: 'missing source measurement',
        },
      },
    };
  }

  const srcResult = normalize(inp.source);
  if (!srcResult.ok) {
    return {
      exitCode: 10,
      body: {
        stage: 'verify-measurement',
        accepted: false,
        rejection: { code: srcResult.code, spec_ref: srcResult.spec_ref, message: 'source measurement invalid' },
      },
    };
  }
  const source = srcResult.measurement;

  let target: AttestationMeasurement | null = null;
  if (inp.target) {
    const t = normalize(inp.target);
    if (!t.ok) {
      return {
        exitCode: 10,
        body: {
          stage: 'verify-measurement',
          accepted: false,
          rejection: { code: t.code, spec_ref: t.spec_ref, message: 'target measurement invalid' },
        },
      };
    }
    target = t.measurement;
  }

  const sourceFp = await measurementFingerprint(source);
  const targetFp = target ? await measurementFingerprint(target) : null;

  if (target) {
    try {
      compareMeasurements(source, target);
    } catch (e) {
      const c = classify(e, source, target);
      return {
        exitCode: 10,
        body: {
          stage: 'verify-measurement',
          accepted: false,
          rejection: { code: c.code, spec_ref: c.spec_ref, message: (e as Error).message },
        },
      };
    }
  }

  return {
    exitCode: 0,
    body: {
      stage: 'verify-measurement',
      accepted: true,
      outputs: {
        source_fingerprint_hex: sourceFp,
        target_fingerprint_hex: targetFp,
      },
    },
  };
}
