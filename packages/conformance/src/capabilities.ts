/**
 * Capabilities for tinfoil-js. Read by the harness once per SDK and used
 * to auto-skip fixtures that target unsupported stages.
 *
 * Keep this in lockstep with what verify-* actually implements. Until
 * verify-sigstore is wired to @tinfoilsh/verifier, it MUST NOT appear in
 * stages_supported — fixtures will then be cleanly skipped.
 */

// Pinned to the workspace version of @tinfoilsh/verifier so the dashboard
// shows which release of the verifier this binary was built against.
// We can't `require('@tinfoilsh/verifier/package.json')` because the verifier
// package's exports map doesn't expose package.json; resolve via the package
// root instead.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
const _require = createRequire(import.meta.url);
let sdkVersion = '0.0.0';
try {
  const verifierEntry = _require.resolve('@tinfoilsh/verifier');
  // Walk up until we find package.json with name "@tinfoilsh/verifier".
  let cur = dirname(verifierEntry);
  for (let i = 0; i < 6; i++) {
    try {
      const pj = JSON.parse(readFileSync(join(cur, 'package.json'), 'utf-8'));
      if (pj.name === '@tinfoilsh/verifier' && typeof pj.version === 'string') {
        sdkVersion = pj.version;
        break;
      }
    } catch {
      /* keep walking */
    }
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
} catch {
  /* leave default */
}

export interface Capabilities {
  schema_version: '1';
  sdk: string;
  sdk_version: string;
  stages_supported: string[];
  sigstore: {
    trust_root_loading: 'configurable' | 'embedded-only';
    verification_time_override:
      | 'supported'
      | 'system-clock-only'
      | 'bundle-supplied-only';
    policy_fields_configurable: Record<string, boolean>;
    predicate_types_understood: string[];
  };
  measurement: {
    compare_multiplatform_to_tdx_supported: boolean;
  };
  attestation_tdx: {
    supported: boolean;
    injected_collateral_supported: boolean;
  };
  attestation_sev: {
    supported: boolean;
    injected_collateral_supported: boolean;
    extended_checks_supported: boolean;
    verification_time_override: 'supported' | 'system-clock-only';
    amd_root_ca_injection_supported: boolean;
  };
  platforms_supported: ('sev-snp' | 'tdx')[];
  transport_modes_supported: ('tls-pinning' | 'ehbp')[];
  flow_modes_supported: ('standard' | 'bundle' | 'pinned')[];
  known_quirks: Record<string, unknown>;
}

export function capabilities(): Capabilities {
  return {
    schema_version: '1',
    sdk: 'tinfoil-js',
    sdk_version: sdkVersion,
    stages_supported: [
      'verify-sigstore',
      'verify-measurement',
      'verify-hardware-measurements',
      'verify-attestation-sev',
    ],
    sigstore: {
      trust_root_loading: 'configurable',
      // sigstore-browser scopes cert chain validity to bundle-supplied times
      // (cert.NotBefore, Rekor integratedTime) — hermetic on the system clock
      // by construction. The fixture's verification_time_unix isn't consulted.
      verification_time_override: 'bundle-supplied-only',
      policy_fields_configurable: {
        oidc_issuer: true,
        workflow_ref_prefix: true,
        workflow_repository: true,
        predicate_types_allowed: true,
        in_toto_statement_types_allowed: true,
        payload_type: true,
        tlog_entries_min: false,
        tlog_entries_max: false,
        sct_min: false,
        observer_timestamps_min: false,
      },
      predicate_types_understood: [
        'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1',
      ],
      legacy_bundle_format_supported: true,
      accepts_multi_tlog_entries: true,
      oidc_issuer_v2_preferred: true,
      scts_count_distinguish_missing_vs_duplicate: true,
      rejects_duplicate_sct_log: true,
      checks_only_subject_0: true,
      in_toto_statement_tolerates_extra_fields: true,
    } as any,
    measurement: {
      // tinfoil-js's compareMeasurements only handles same-type and MP↔SEV.
      // The MP↔TDX path (SPEC §7.3.2 and its §7.3.4 reverse) throws
      // "Incompatible measurement types". Declared honestly until the lib gains
      // the TDX path; gated fixtures skip cleanly meanwhile.
      compare_multiplatform_to_tdx_supported: false,
    },
    attestation_tdx: {
      // @tinfoilsh/verifier doesn't include a TDX path today —
      // PredicateType.TdxGuestV2 isn't in the enum, and compareMeasurements
      // doesn't handle TDX targets. Declared false so attestation-tdx
      // fixtures skip cleanly until a TDX-aware verifier ships.
      supported: false,
      injected_collateral_supported: false,
    },
    attestation_sev: {
      // @tinfoilsh/verifier exposes verifyAttestation(doc, vcekBase64) with
      // embedded ARK/ASK constants for Genoa. VCEK is supplied inline.
      supported: true,
      injected_collateral_supported: true,
      // The conformance binary enforces every policy.expected_*_hex pin
      // (measurement, host_data, report_data, id_key_digest,
      // author_key_digest) and policy.enforce_spec_defaults checks
      // (DEBUG bit, reserved-MBO/MBZ) post-lib-verification.
      extended_checks_supported: true,
      // CertificateChain.verifyChain() uses `new Date()` unconditionally —
      // fixtures pinning verification_check_date_unix outside the real-now
      // window aren't honored. Fixture 240-vcek-expired gates on
      // verification_time_override=supported and skips cleanly here.
      verification_time_override: 'system-clock-only',
      // ARK_CERT / ASK_CERT are frozen bytes constants bundled into
      // @tinfoilsh/verifier's CertificateChain. No public injection API.
      // Phase 4B-SEV synth-chain fixtures (600-604, 700-703) skip cleanly
      // on JS until the verifier exposes a trust-root override.
      amd_root_ca_injection_supported: false,
    },
    platforms_supported: ['sev-snp'],
    transport_modes_supported: ['tls-pinning', 'ehbp'],
    flow_modes_supported: ['bundle'],
    known_quirks: {
      'sigstore.dcode_substring_match':
        'cert-verify.ts uses .includes() for .hpke./.hatt. SAN filtering (recon finding, separate fix)',
      'inference.ehbp_unverified_mode_exists':
        'createUnverifiedEncryptedBodyFetch bypasses attestation — must NEVER be used in production',
    },
  };
}
