/**
 * verify-sigstore stub.
 *
 * TODO(tinfoil-conformance): wire to @tinfoilsh/verifier's sigstore path.
 * The current `verifySigstoreBundle()` in @tinfoilsh/verifier delegates to
 * `@freedomofpress/sigstore-browser` which (a) embeds its own trust root
 * and (b) uses system clock for cert validity. To pass conformance fixtures
 * we need to:
 *
 *   1. Plumb `trust_root_b64` through to `verifier.loadSigstoreRoot()`
 *      instead of the hardcoded `sigstoreTrustedRoot` import.
 *   2. Plumb `verification_time_unix` to override `new Date()` in
 *      cert-validity checks.
 *   3. Surface policy knobs (workflow_ref_prefix, predicate_types_allowed,
 *      payload_type, tlog_entries_{min,max}, sct_min) as the policy object
 *      rather than the current hardcoded values.
 *   4. Fix the partial-extraction bug for SnpTdxMultiPlatformV1: emit
 *      `registers = [snp_measurement, rtmr1, rtmr2]`, not `[snp_measurement]`
 *      (see capabilities.known_quirks).
 *
 * Until those land, the binary declares stages_supported=[] in capabilities
 * and the harness auto-skips Sigstore fixtures. This module is kept thin so
 * the wiring PR has an obvious landing spot.
 */

interface VerifyResultBody {
  stage: 'verify-sigstore';
  accepted: boolean;
  outputs?: Record<string, unknown>;
  rejection?: { code: string; spec_ref?: string; message?: string };
}

export interface VerifyResult {
  exitCode: number;
  body: VerifyResultBody;
}

export async function verifySigstore(input: unknown): Promise<VerifyResult> {
  if (typeof input !== 'object' || input === null) {
    return {
      exitCode: 30,
      body: {
        stage: 'verify-sigstore',
        accepted: false,
        rejection: {
          code: 'BUNDLE_MALFORMED',
          spec_ref: '5.2',
          message: 'input is not a JSON object',
        },
      },
    };
  }
  if ((input as { schema_version?: unknown }).schema_version !== '1') {
    return {
      exitCode: 30,
      body: {
        stage: 'verify-sigstore',
        accepted: false,
        rejection: {
          code: 'BUNDLE_MALFORMED',
          spec_ref: '5.2',
          message: 'input.schema_version != "1"',
        },
      },
    };
  }

  return {
    exitCode: 20,
    body: {
      stage: 'verify-sigstore',
      accepted: false,
      rejection: {
        code: 'TRUST_ROOT_INVALID',
        spec_ref: '5.1',
        message:
          'stub: verify-sigstore not yet implemented in tinfoil-js conformance binary',
      },
    },
  };
}
