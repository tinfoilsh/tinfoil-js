/**
 * verify-attestation-sev for tinfoil-js.
 *
 * Calls @tinfoilsh/verifier's exported verifyAttestation() on a wrapped
 * AttestationDocument constructed from the fixture's gzipped report body +
 * base64-encoded VCEK DER. After lib verification succeeds, decodes the
 * 1184-byte SEV-SNP v3 report locally to emit the same body_fields shape
 * as the Go conformance binary (cross-SDK pinned-output parity).
 *
 * ARK/ASK source: @tinfoilsh/verifier embeds ARK_CERT/ASK_CERT constants
 * for Genoa — fully hermetic by construction. The fixture's
 * amd_root_ca_pem / ask_pem overrides are not applied (no lib API).
 *
 * Verification time: @tinfoilsh/verifier's CertificateChain.verifyChain()
 * uses `new Date()` unconditionally. Fixtures setting
 * expiration_check_date_unix outside the real-now window aren't honored;
 * capabilities declares verification_time_override='system-clock-only'
 * and 240-vcek-expired skips on JS.
 *
 * Policy enforcement: tinfoil-js's defaultValidationOptions hardcodes
 * Tinfoil's production policy (smt=true, debug=false, etc.). Caller-
 * supplied policy.expected_*_hex pins are enforced HERE in the
 * conformance binary after lib verification succeeds, mirroring the Go
 * binary's enforceSevPolicy.
 */

import {
  verifyAttestation,
  PredicateType,
  type AttestationDocument,
} from '@tinfoilsh/verifier';
import { gunzipSync } from 'node:zlib';

interface PolicyInput {
  expected_measurement_hex?: string;
  expected_host_data_hex?: string;
  expected_report_data_hex?: string;
  expected_id_key_digest_hex?: string;
  expected_author_key_digest_hex?: string;
  min_tcb_bl_spl?: number;
  min_tcb_tee_spl?: number;
  min_tcb_snp_spl?: number;
  min_tcb_ucode_spl?: number;
  enforce_spec_defaults?: boolean;
}

interface Input {
  schema_version: string;
  attestation_doc_b64: string;
  vcek_der_b64: string;
  amd_root_ca_pem?: string;
  ask_pem?: string;
  expiration_check_date_unix?: number;
  policy?: PolicyInput;
}

interface VerifyResultBody {
  stage: 'verify-attestation-sev';
  accepted: boolean;
  outputs?: Record<string, unknown>;
  rejection?: { code: string; spec_ref?: string; message?: string };
}

export interface VerifyResult {
  exitCode: number;
  body: VerifyResultBody;
}

const EXIT_ACCEPT = 0;
const EXIT_REJECT = 10;
const EXIT_BAD_INPUT = 30;

function reject(
  code: string,
  specRef: string,
  message: string,
  exitCode = EXIT_REJECT,
): VerifyResult {
  return {
    exitCode,
    body: {
      stage: 'verify-attestation-sev',
      accepted: false,
      rejection: { code, spec_ref: specRef, message },
    },
  };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function readU32LE(b: Uint8Array, off: number): number {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}

function readU64LE(b: Uint8Array, off: number): bigint {
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) | BigInt(b[off + i]);
  return n;
}

function u64Hex(n: bigint): string {
  return n.toString(16).padStart(16, '0');
}

function decodeBodyFields(report: Uint8Array): Record<string, unknown> {
  const policy = readU64LE(report, 0x08);
  const currentTcb = readU64LE(report, 0x38);
  const platformInfo = readU64LE(report, 0x40);

  const bit = (n: bigint, i: number): boolean => ((n >> BigInt(i)) & 1n) === 1n;

  return {
    version: readU32LE(report, 0x00),
    guest_svn: readU32LE(report, 0x04),
    policy_hex: u64Hex(policy),
    policy_decoded: {
      abi_minor: Number(policy & 0xffn),
      abi_major: Number((policy >> 8n) & 0xffn),
      smt: bit(policy, 16),
      reserved_mbo: bit(policy, 17),
      migrate_ma: bit(policy, 18),
      debug: bit(policy, 19),
      single_socket: bit(policy, 20),
      cxl_allow: bit(policy, 21),
      mem_aes_256_xts: bit(policy, 22),
      raplmsr_dis: bit(policy, 23),
      ciphertext_hiding_dram: bit(policy, 24),
    },
    family_id_hex: toHex(report.slice(0x10, 0x20)),
    image_id_hex: toHex(report.slice(0x20, 0x30)),
    vmpl: readU32LE(report, 0x30),
    signature_algo: readU32LE(report, 0x34),
    current_tcb_hex: u64Hex(currentTcb),
    current_tcb_decoded: {
      bl_spl: Number(currentTcb & 0xffn),
      tee_spl: Number((currentTcb >> 8n) & 0xffn),
      snp_spl: Number((currentTcb >> 48n) & 0xffn),
      ucode_spl: Number((currentTcb >> 56n) & 0xffn),
    },
    platform_info_hex: u64Hex(platformInfo),
    platform_info_decoded: {
      smt_en: bit(platformInfo, 0),
      tsme_en: bit(platformInfo, 1),
      ecc_en: bit(platformInfo, 2),
      rapl_dis: bit(platformInfo, 3),
      ciphertext_hiding: bit(platformInfo, 4),
    },
    signer_info_hex: readU32LE(report, 0x48).toString(16).padStart(8, '0'),
    report_data_hex: toHex(report.slice(0x50, 0x90)),
    measurement_hex: toHex(report.slice(0x90, 0x90 + 48)),
    host_data_hex: toHex(report.slice(0xc0, 0xc0 + 32)),
    id_key_digest_hex: toHex(report.slice(0xe0, 0xe0 + 48)),
    author_key_digest_hex: toHex(report.slice(0x110, 0x110 + 48)),
    report_id_hex: toHex(report.slice(0x140, 0x140 + 32)),
    report_id_ma_hex: toHex(report.slice(0x160, 0x160 + 32)),
    reported_tcb_hex: toHex(report.slice(0x180, 0x180 + 8)),
    chip_id_hex: toHex(report.slice(0x1a0, 0x1a0 + 64)),
    committed_tcb_hex: toHex(report.slice(0x1e8, 0x1e8 + 8)),
    current_build: report[0x1f0],
    current_minor: report[0x1f1],
    current_major: report[0x1f2],
    committed_build: report[0x1f4],
    committed_minor: report[0x1f5],
    committed_major: report[0x1f6],
    launch_tcb_hex: toHex(report.slice(0x1f8, 0x1f8 + 8)),
  };
}

function normalizeHex(s: string | undefined): string {
  return (s ?? '').trim().toLowerCase();
}

function enforcePolicy(
  report: Uint8Array,
  policy: PolicyInput | undefined,
): { code: string; specRef: string; message: string } | null {
  if (!policy) return null;

  const checks: [string, string, string, Uint8Array, string | undefined][] = [
    [
      'MEASUREMENT_MISMATCH',
      '3.8',
      'measurement',
      report.slice(0x90, 0x90 + 48),
      policy.expected_measurement_hex,
    ],
    [
      'HOST_DATA_MISMATCH',
      '8.3',
      'host_data',
      report.slice(0xc0, 0xc0 + 32),
      policy.expected_host_data_hex,
    ],
    [
      'REPORT_DATA_MISMATCH',
      '8.2',
      'report_data',
      report.slice(0x50, 0x90),
      policy.expected_report_data_hex,
    ],
    [
      'ID_KEY_DIGEST_MISMATCH',
      '3.1.1',
      'id_key_digest',
      report.slice(0xe0, 0xe0 + 48),
      policy.expected_id_key_digest_hex,
    ],
    [
      'AUTHOR_KEY_DIGEST_MISMATCH',
      '3.1.1',
      'author_key_digest',
      report.slice(0x110, 0x110 + 48),
      policy.expected_author_key_digest_hex,
    ],
  ];

  for (const [code, ref, field, actual, expected] of checks) {
    const exp = normalizeHex(expected);
    if (!exp) continue;
    if (toHex(actual) !== exp) {
      return {
        code,
        specRef: ref,
        message: `${field} ${toHex(actual)} != policy expected ${exp}`,
      };
    }
  }

  const currentTcb = readU64LE(report, 0x38);
  const tcbBlSpl = Number(currentTcb & 0xffn);
  const tcbTeeSpl = Number((currentTcb >> 8n) & 0xffn);
  const tcbSnpSpl = Number((currentTcb >> 48n) & 0xffn);
  const tcbUcodeSpl = Number((currentTcb >> 56n) & 0xffn);

  const tcbMin: [string, number, number | undefined][] = [
    ['bl_spl', tcbBlSpl, policy.min_tcb_bl_spl],
    ['tee_spl', tcbTeeSpl, policy.min_tcb_tee_spl],
    ['snp_spl', tcbSnpSpl, policy.min_tcb_snp_spl],
    ['ucode_spl', tcbUcodeSpl, policy.min_tcb_ucode_spl],
  ];
  for (const [name, actual, min] of tcbMin) {
    if (min !== undefined && actual < min) {
      return {
        code: 'TCB_OUT_OF_DATE',
        specRef: '3.7',
        message: `tcb.${name}=${actual} below minimum ${min}`,
      };
    }
  }

  if (policy.enforce_spec_defaults) {
    const guestPolicy = readU64LE(report, 0x08);
    const bit = (n: bigint, i: number): boolean => ((n >> BigInt(i)) & 1n) === 1n;
    if (bit(guestPolicy, 19)) {
      return {
        code: 'GUEST_POLICY_DEBUG_SET',
        specRef: '3.7',
        message: `guest_policy DEBUG bit (19) is set (policy=${u64Hex(guestPolicy)})`,
      };
    }
    if (!bit(guestPolicy, 17)) {
      return {
        code: 'GUEST_POLICY_RESERVED_BIT_SET',
        specRef: '3.7',
        message: `guest_policy reserved-MBO bit (17) is clear (policy=${u64Hex(guestPolicy)})`,
      };
    }
    const reservedMBZ = 0xfffffffffe000000n;
    if ((guestPolicy & reservedMBZ) !== 0n) {
      return {
        code: 'GUEST_POLICY_RESERVED_BIT_SET',
        specRef: '3.7',
        message: `guest_policy reserved-MBZ bit (≥25) set (policy=${u64Hex(guestPolicy)})`,
      };
    }
  }

  return null;
}

function classifyLibError(err: unknown): { code: string; specRef: string } {
  // Walk the error chain — @tinfoilsh/verifier wraps inner causes with
  // `wrapOrThrow`, so the most specific message is on the innermost cause.
  const parts: string[] = [];
  let cur: unknown = err;
  for (let i = 0; i < 8 && cur; i++) {
    if (cur instanceof Error) {
      parts.push(cur.message);
      cur = (cur as { cause?: unknown }).cause;
    } else {
      parts.push(String(cur));
      break;
    }
  }
  const msg = parts.join(' || ').toLowerCase();

  // Order: specific patterns before generic. "report signature" must win
  // over "vcek" since the lib phrases sig failures as "report ... VCEK key".
  if (msg.includes('expired') || msg.includes('not yet valid')) {
    return { code: 'VCEK_EXPIRED', specRef: '3.3.3' };
  }
  if (msg.includes('hwid')) {
    return { code: 'VCEK_HWID_MISMATCH', specRef: '3.4.4' };
  }
  if (msg.includes('vcek tcb') || msg.includes('tcb mismatch')) {
    return { code: 'VCEK_TCB_MISMATCH', specRef: '3.4.3' };
  }
  if (msg.includes('report signature') || msg.includes('report ... vcek key')
      || (msg.includes('signature is invalid') && msg.includes('report'))) {
    return { code: 'REPORT_SIGNATURE_INVALID', specRef: '3.6' };
  }
  if (msg.includes('ask') && msg.includes('not signed by ark')) {
    return { code: 'ASK_INVALID', specRef: '3.3.2' };
  }
  if (msg.includes('ark') && msg.includes('self-sign')) {
    return { code: 'ARK_UNTRUSTED', specRef: '3.3.1' };
  }
  if (
    msg.includes('amd certificate chain verification failed') ||
    msg.includes('vcek certificate signature verification failed') ||
    (msg.includes('vcek') && (msg.includes('chain') || msg.includes('signature'))) ||
    msg.includes('malformed certificate') ||
    msg.includes('invalid vcek')
  ) {
    return { code: 'VCEK_CHAIN_INVALID', specRef: '3.3.5' };
  }
  if (
    msg.includes('failed to decode attestation document') ||
    msg.includes('failed to parse') ||
    msg.includes('unsupported processor') ||
    msg.includes('unsupported signing key') ||
    msg.includes('invalid base64') ||
    msg.includes('report length')
  ) {
    return { code: 'REPORT_FORMAT_UNSUPPORTED', specRef: '3.1' };
  }
  return { code: 'QV_RESULT_TERMINAL_UNSPECIFIED', specRef: '3' };
}

export interface SevRejection {
  code: string;
  specRef: string;
  message: string;
}

export interface SevSuccess {
  ok: true;
  report: Uint8Array;
  bodyFields: Record<string, unknown>;
  measurement: { type: string; registers: string[] };
}

/** Inner SEV verification: parses input, calls @tinfoilsh/verifier, runs
 *  policy enforcement, and returns either a SevSuccess (decoded fields) or
 *  a rejection triple. Shared by cmd_verify_attestation_sev and verify-full's
 *  chaining. The verify-full envelope's nested attestation_sev block omits
 *  schema_version; treat missing as "1". */
export async function runVerifyAttestationSevInner(
  input: Input,
): Promise<SevSuccess | { ok: false; rej: SevRejection }> {
  const sv = input.schema_version ?? '1';
  if (sv !== '1') {
    return { ok: false, rej: { code: 'REPORT_FORMAT_UNSUPPORTED', specRef: '3.1', message: 'schema_version != "1"' } };
  }
  if (!input.attestation_doc_b64 || !input.vcek_der_b64) {
    return { ok: false, rej: { code: 'REPORT_FORMAT_UNSUPPORTED', specRef: '3.1', message: 'attestation_doc_b64 and vcek_der_b64 are required' } };
  }
  let report: Uint8Array;
  try {
    const gzBytes = Buffer.from(input.attestation_doc_b64, 'base64');
    report = new Uint8Array(gunzipSync(gzBytes));
  } catch (e) {
    return { ok: false, rej: { code: 'REPORT_FORMAT_UNSUPPORTED', specRef: '3.1', message: `gzip decompress failed: ${(e as Error).message}` } };
  }
  if (report.length < 1184) {
    return { ok: false, rej: { code: 'REPORT_TRUNCATED', specRef: '3.1', message: `SEV report is ${report.length} bytes, expected ≥1184` } };
  }
  const doc: AttestationDocument = {
    format: PredicateType.SevGuestV2,
    body: input.attestation_doc_b64,
  };
  try {
    await verifyAttestation(doc, input.vcek_der_b64);
  } catch (e) {
    const { code, specRef } = classifyLibError(e);
    return { ok: false, rej: { code, specRef, message: (e as Error).message ?? String(e) } };
  }
  const policyViolation = enforcePolicy(report, input.policy);
  if (policyViolation) {
    return { ok: false, rej: policyViolation };
  }
  const bodyFields = decodeBodyFields(report) as Record<string, unknown>;
  const measurement = {
    type: 'https://tinfoil.sh/predicate/sev-snp-guest/v2',
    registers: [bodyFields.measurement_hex as string],
  };
  return { ok: true, report, bodyFields, measurement };
}

export async function verifyAttestationSev(raw: unknown): Promise<VerifyResult> {
  if (typeof raw !== 'object' || raw === null) {
    return reject(
      'REPORT_FORMAT_UNSUPPORTED',
      '3.1',
      'input is not a JSON object',
      EXIT_BAD_INPUT,
    );
  }
  const input = raw as Input;
  // cmd_verify_attestation_sev requires schema_version explicitly (the
  // verify-full envelope's attestation_sev sub-block omits it).
  if (input.schema_version !== '1') {
    return reject(
      'REPORT_FORMAT_UNSUPPORTED',
      '3.1',
      `schema_version != "1"`,
      EXIT_BAD_INPUT,
    );
  }
  const result = await runVerifyAttestationSevInner(input);
  if (!result.ok) {
    return reject(result.rej.code, result.rej.specRef, result.rej.message);
  }
  return {
    exitCode: EXIT_ACCEPT,
    body: {
      stage: 'verify-attestation-sev',
      accepted: true,
      outputs: {
        measurement: result.measurement,
        body_fields: result.bodyFields,
      },
    },
  };
}
