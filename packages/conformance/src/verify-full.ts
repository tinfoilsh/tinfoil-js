/**
 * verify-full for tinfoil-js.
 *
 * Orchestrates the SPEC §11 end-to-end flow: Sigstore-attested measurement
 * cross-checked against a freshly-fetched hardware attestation. The
 * conformance binary chains the per-stage entry points (the *Inner exports
 * from verify-sigstore and verify-attestation-sev) so any sub-stage
 * rejection surfaces with its SPEC-anchored rejection code AND the
 * sub-stage that produced it.
 */

import {
  compareMeasurements,
  PredicateType,
  type AttestationMeasurement,
} from '@tinfoilsh/verifier';
import { runVerifySigstoreInner } from './verify-sigstore.js';
import { runVerifyAttestationSevInner } from './verify-attestation-sev.js';

interface PinnedMeasurement {
  type: string;
  registers: unknown;
}

interface VerifyFullInput {
  schema_version: string;
  mode: 'standard' | 'bundle' | 'pinned' | string;
  sigstore?: any;
  attestation_sev?: any;
  attestation_tdx?: any;
  pinned_measurement?: PinnedMeasurement;
}

interface VerifyFullBody {
  stage: 'verify-full';
  accepted: boolean;
  outputs?: Record<string, unknown>;
  rejection?: { code: string; stage?: string; spec_ref?: string; message?: string };
}

export interface VerifyFullResult {
  exitCode: number;
  body: VerifyFullBody;
}

const EXIT_ACCEPT = 0;
const EXIT_REJECT = 10;

function emitFullRejection(code: string, stage: string, specRef: string, message: string): VerifyFullResult {
  return {
    exitCode: EXIT_REJECT,
    body: {
      stage: 'verify-full',
      accepted: false,
      rejection: { code, stage, spec_ref: specRef, message },
    },
  };
}

function predicateFromUri(uri: string): PredicateType | null {
  switch (uri) {
    case 'https://tinfoil.sh/predicate/sev-snp-guest/v2':
      return PredicateType.SevGuestV2;
    case 'https://tinfoil.sh/predicate/tdx-guest/v2':
      // @tinfoilsh/verifier doesn't model TDX as of this writing; predicate
      // type left enum-undeclared. Returning null surfaces as MEASUREMENT_
      // TYPE_UNKNOWN at the call site.
      return null;
    case 'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1':
      return PredicateType.SnpTdxMultiplatformV1;
    default:
      return null;
  }
}

/** Map a thrown compareMeasurements error to (code, spec_ref). The lib's
 *  AttestationError messages are stable enough to bucket by substring. */
function classifyCompareError(err: unknown): { code: string; specRef: string } {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (msg.includes('rtmr3') || msg.includes('rtmr_3')) {
    return { code: 'MEASUREMENT_RTMR3_NONZERO', specRef: '7.3.2' };
  }
  if (msg.includes('incompatible measurement types') || msg.includes('incompatible')) {
    return { code: 'MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED', specRef: '7.3.5' };
  }
  return { code: 'MEASUREMENT_MISMATCH', specRef: '7.3' };
}

function asAttestationMeasurement(m: { type: string; registers: unknown }): AttestationMeasurement | null {
  const pt = predicateFromUri(m.type);
  if (pt === null || !Array.isArray(m.registers) || !m.registers.every((r) => typeof r === 'string')) {
    return null;
  }
  return {
    type: pt,
    registers: (m.registers as string[]).map((r) => r.toLowerCase()),
  };
}

type SevStage = Awaited<ReturnType<typeof runVerifyAttestationSevInner>> & { ok: true };

/** Verify the SEV attestation and compare its measurement with `expected`
 *  (the Sigstore or pinned measurement). Shared by every verify-full mode. */
async function verifySevAgainst(
  expected: AttestationMeasurement,
  attestationSev: unknown,
): Promise<{ ok: true; sev: SevStage } | { ok: false; result: VerifyFullResult }> {
  let sevResult: Awaited<ReturnType<typeof runVerifyAttestationSevInner>>;
  try {
    sevResult = await runVerifyAttestationSevInner(attestationSev as any);
  } catch (e) {
    return { ok: false, result: emitFullRejection('REPORT_FORMAT_UNSUPPORTED', 'verify-attestation-sev', '3.1',
      `malformed attestation_sev input: ${(e as Error).message ?? String(e)}`) };
  }
  if (!sevResult.ok) {
    return { ok: false, result: emitFullRejection(sevResult.rej.code, 'verify-attestation-sev', sevResult.rej.specRef, sevResult.rej.message) };
  }
  const attM = asAttestationMeasurement(sevResult.measurement);
  if (attM === null) {
    return { ok: false, result: emitFullRejection('MEASUREMENT_TYPE_UNKNOWN', 'verify-measurement', '2.3',
      `unrecognized attestation measurement type: ${sevResult.measurement.type}`) };
  }
  try {
    compareMeasurements(expected, attM);
  } catch (e) {
    const { code, specRef } = classifyCompareError(e);
    return { ok: false, result: emitFullRejection(code, 'verify-measurement', specRef, (e as Error).message ?? String(e)) };
  }
  return { ok: true, sev: sevResult };
}

export async function verifyFull(raw: unknown): Promise<VerifyFullResult> {
  if (typeof raw !== 'object' || raw === null) {
    return emitFullRejection('BUNDLE_MALFORMED', 'verify-full', '11',
      'input is not a JSON object');
  }
  const input = raw as VerifyFullInput;
  if (input.schema_version !== '1') {
    return emitFullRejection('BUNDLE_MALFORMED', 'verify-full', '11',
      'input.schema_version != "1"');
  }

  if (input.mode === 'standard' || input.mode === 'bundle') {
    if (typeof input.sigstore !== 'object' || input.sigstore === null) {
      return emitFullRejection('BUNDLE_MALFORMED', 'verify-full', '11.1',
        'mode="standard"/"bundle" requires "sigstore" input block');
    }
    let sigResult: Awaited<ReturnType<typeof runVerifySigstoreInner>>;
    try {
      sigResult = await runVerifySigstoreInner(input.sigstore);
    } catch (e) {
      return emitFullRejection('BUNDLE_MALFORMED', 'verify-sigstore', '5.2',
        `malformed sigstore input: ${(e as Error).message ?? String(e)}`);
    }
    if (!sigResult.ok) {
      return emitFullRejection(sigResult.rej.code, 'verify-sigstore', sigResult.rej.spec_ref, sigResult.rej.message);
    }
    // SPEC §7.3 lowercase normalization before comparison.
    const sigMeasurement: AttestationMeasurement = {
      type: sigResult.v.measurement.type,
      registers: sigResult.v.measurement.registers.map((r) => r.toLowerCase()),
    };

    if (typeof input.attestation_sev !== 'object' || input.attestation_sev === null) {
      return emitFullRejection('BUNDLE_MALFORMED', 'verify-full', '11.1',
        'mode="standard"/"bundle" requires attestation_sev (TDX path not wired on JS)');
    }
    const r = await verifySevAgainst(sigMeasurement, input.attestation_sev);
    if (!r.ok) return r.result;

    return {
      exitCode: EXIT_ACCEPT,
      body: {
        stage: 'verify-full',
        accepted: true,
        outputs: {
          mode: input.mode,
          platform: 'sev-snp',
          sigstore_measurement: sigMeasurement,
          attestation_measurement: r.sev.measurement,
          final_measurement_fingerprint_hex: r.sev.measurement.registers[0],
        },
      },
    };
  }

  if (input.mode === 'pinned') {
    if (typeof input.pinned_measurement !== 'object' || input.pinned_measurement === null) {
      return emitFullRejection('BUNDLE_MALFORMED', 'verify-full', '11.3',
        'mode="pinned" requires "pinned_measurement"');
    }
    const pinM = asAttestationMeasurement(input.pinned_measurement);
    if (pinM === null) {
      return emitFullRejection('MEASUREMENT_TYPE_UNKNOWN', 'verify-full', '2.3',
        `unrecognized or malformed pinned measurement: ${input.pinned_measurement.type}`);
    }
    if (typeof input.attestation_sev !== 'object' || input.attestation_sev === null) {
      return emitFullRejection('BUNDLE_MALFORMED', 'verify-full', '11.3',
        'mode="pinned" requires attestation_sev');
    }
    const r = await verifySevAgainst(pinM, input.attestation_sev);
    if (!r.ok) return r.result;
    return {
      exitCode: EXIT_ACCEPT,
      body: {
        stage: 'verify-full',
        accepted: true,
        outputs: {
          mode: 'pinned',
          platform: 'sev-snp',
          attestation_measurement: r.sev.measurement,
          final_measurement_fingerprint_hex: r.sev.measurement.registers[0],
        },
      },
    };
  }

  return emitFullRejection('BUNDLE_MALFORMED', 'verify-full', '11',
    `unknown mode ${JSON.stringify(input.mode)} (allowed: standard, bundle, pinned)`);
}
