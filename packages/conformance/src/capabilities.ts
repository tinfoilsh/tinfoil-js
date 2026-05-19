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
    verification_time_override: 'supported' | 'system-clock-only';
    policy_fields_configurable: Record<string, boolean>;
    predicate_types_understood: string[];
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
    // verify-sigstore is intentionally NOT listed yet — this is the stub
    // commit. Wiring it up requires extending @tinfoilsh/verifier to accept
    // an inline trust root and a fixed verification time, instead of
    // delegating those to @freedomofpress/sigstore-browser internals.
    stages_supported: [],
    sigstore: {
      trust_root_loading: 'embedded-only',
      verification_time_override: 'system-clock-only',
      policy_fields_configurable: {
        oidc_issuer: false,
        workflow_ref_prefix: false,
        workflow_repository: true,
        predicate_types_allowed: false,
        in_toto_statement_types_allowed: false,
        payload_type: false,
        tlog_entries_min: false,
        tlog_entries_max: false,
        sct_min: false,
        observer_timestamps_min: false,
      },
      predicate_types_understood: [
        'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1',
      ],
    },
    platforms_supported: ['sev-snp'],
    transport_modes_supported: ['tls-pinning', 'ehbp'],
    flow_modes_supported: ['bundle'],
    known_quirks: {
      'sigstore.predicate_partial_extraction':
        'JS extracts only snp_measurement from SnpTdxMultiPlatformV1 — drops rtmr1/rtmr2 (recon finding, to be fixed)',
      'sigstore.dcode_substring_match': true,
      'inference.ehbp_unverified_mode_exists':
        'createUnverifiedEncryptedBodyFetch bypasses attestation — must NEVER be used in production',
    },
  };
}
