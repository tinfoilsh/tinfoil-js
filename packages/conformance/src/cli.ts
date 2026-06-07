#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  PckCertificateChain,
  parsePckExtensions,
  parseTdxQuote,
  verifyQeReportDataBinding,
  verifyQeReportSignature,
  verifyQuoteSignature,
  type TdxQuote,
} from '@tinfoilsh/verifier';

const EXIT_ACCEPT = 0;
const EXIT_REJECT = 10;
const EXIT_UNSUPPORTED = 20;
const EXIT_BAD_INPUT = 30;
const STAGE = 'verify-attestation-tdx';
const TDX_GUEST_V2_URI = 'https://tinfoil.sh/predicate/tdx-guest/v2';

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function emit(body: JsonRecord, exitCode: number): number {
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  return exitCode;
}

function badInput(message: string): number {
  process.stderr.write(`${message}\n`);
  return EXIT_BAD_INPUT;
}

function reject(code: string, specRef: string, message: string): number {
  return emit({
    stage: STAGE,
    accepted: false,
    rejection: { code, spec_ref: specRef, message },
  }, EXIT_REJECT);
}

function unsupported(message: string): number {
  return emit({
    stage: STAGE,
    accepted: false,
    rejection: { code: 'UNSUPPORTED', spec_ref: '4.7', message },
  }, EXIT_UNSUPPORTED);
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function classifyTdxError(error: unknown): [string, string] {
  const msg = messageOf(error).toLowerCase();

  if (msg.includes('invalid tee type') || msg.includes('tee type')) {
    return ['WRONG_TEE_TYPE', 'A.3.1'];
  }
  if (msg.includes('attestation key type') || msg.includes('unsupported') && msg.includes('key type')) {
    return ['ATTESTATION_KEY_TYPE_UNSUPPORTED', 'A.3.1'];
  }
  if (msg.includes('qe vendor') || msg.includes('unknown qe')) {
    return ['QE_VENDOR_UNKNOWN', 'A.3.1'];
  }
  if (
    msg.includes('quote too short') ||
    msg.includes('quote too small') ||
    msg.includes('truncated') ||
    msg.includes('minimum') && msg.includes('size')
  ) {
    return ['QUOTE_TRUNCATED', 'A.3'];
  }
  if (
    msg.includes('certification data') ||
    msg.includes('size mismatch') ||
    msg.includes('data size') ||
    msg.includes('offset is outside') ||
    msg.includes('outside the bounds')
  ) {
    return ['QUOTE_FORMAT_UNSUPPORTED', 'A.3.9'];
  }
  if (msg.includes('unsupported quote version') || msg.includes('quote version') || msg.includes('version') && msg.includes('supported')) {
    return ['QUOTE_FORMAT_UNSUPPORTED', 'A.3.1'];
  }
  if ((msg.includes('qe report') || msg.includes('qe_report')) && msg.includes('signature')) {
    return ['QE_REPORT_SIGNATURE_INVALID', '4.4'];
  }
  if (msg.includes('expired') || msg.includes('not yet valid')) {
    return ['PCK_EXPIRED', '4.2'];
  }
  if (msg.includes('pck') && msg.includes('chain')) {
    return ['PCK_CHAIN_INVALID', '4.2'];
  }
  if (msg.includes('certificate chain') || msg.includes('cert chain')) {
    return ['PCK_CHAIN_INVALID', '4.2'];
  }
  if ((msg.includes('pck') || msg.includes('intermediate') || msg.includes('root')) && msg.includes('certificate')) {
    return ['PCK_CHAIN_INVALID', '4.2'];
  }
  if (msg.includes('qe report') || msg.includes('qe_report')) {
    return ['QE_REPORT_SIGNATURE_INVALID', '4.4'];
  }
  if (
    msg.includes('ak') && (msg.includes('bind') || msg.includes('report data')) ||
    msg.includes('attestation key') && msg.includes('not endorsed')
  ) {
    return ['AK_BINDING_INVALID', '4.5'];
  }
  if (msg.includes('signature')) {
    return ['QUOTE_SIGNATURE_INVALID', '4.3'];
  }
  if (msg.includes('root') && (msg.includes('trust') || msg.includes('ca'))) {
    return ['ROOT_CA_UNTRUSTED', '4.2'];
  }
  if (msg.includes('format')) {
    return ['QUOTE_FORMAT_UNSUPPORTED', 'A.3'];
  }
  return ['QV_RESULT_TERMINAL_UNSPECIFIED', '4.1.2'];
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToLittleEndianBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function decodeTdAttributes(tdAttrs: Uint8Array): JsonRecord {
  const n = bytesToLittleEndianBigInt(tdAttrs);
  return {
    tud_debug: Boolean(n & (1n << 0n)),
    tud_reserved_nonzero: Boolean(n & 0xFEn),
    sec_reserved_lower_nonzero: Boolean(n & 0x0FFFFF00n),
    sec_sept_ve_disable: Boolean(n & (1n << 28n)),
    sec_reserved_bit29: Boolean(n & (1n << 29n)),
    sec_pks: Boolean(n & (1n << 30n)),
    sec_kl: Boolean(n & (1n << 31n)),
    other_reserved_nonzero: Boolean(n & 0x7FFFFFFF00000000n),
    other_perfmon: Boolean(n & (1n << 63n)),
  };
}

function policyString(policy: JsonRecord, field: string): string | undefined {
  const value = policy[field];
  return typeof value === 'string' ? value : undefined;
}

function expectedHexMatches(expectedHex: string | undefined, got: Uint8Array): boolean {
  if (expectedHex === undefined) {
    return true;
  }
  const normalized = expectedHex.trim().toLowerCase();
  return normalized.length === got.length * 2 && normalized === bytesToHex(got);
}

function enforceExtendedPolicy(quote: TdxQuote, policy: JsonRecord): [string, string] | undefined {
  const pins: Array<[string, Uint8Array, string, string]> = [
    ['expected_td_attributes_hex', quote.body.tdAttributes, 'TD_ATTRIBUTES_MISMATCH', 'td_attributes'],
    ['expected_xfam_hex', quote.body.xfam, 'XFAM_MISMATCH', 'xfam'],
    ['expected_mr_signer_seam_hex', quote.body.mrSignerSeam, 'MR_SIGNER_SEAM_MISMATCH', 'mr_signer_seam'],
    ['expected_seam_attributes_hex', quote.body.seamAttributes, 'SEAM_ATTRIBUTES_MISMATCH', 'seam_attributes'],
    ['expected_mrtd_hex', quote.body.mrTd, 'MRTD_MISMATCH', 'mrtd'],
    ['expected_mr_config_id_hex', quote.body.mrConfigId, 'MR_CONFIG_ID_MISMATCH', 'mr_config_id'],
    ['expected_mr_owner_hex', quote.body.mrOwner, 'MR_OWNER_MISMATCH', 'mr_owner'],
    ['expected_mr_owner_config_hex', quote.body.mrOwnerConfig, 'MR_OWNER_CONFIG_MISMATCH', 'mr_owner_config'],
    ['expected_rtmr3_hex', quote.body.rtmrs[3] ?? new Uint8Array(), 'RTMR3_NONZERO', 'rtmr3'],
    ['expected_report_data_hex', quote.body.reportData, 'REPORT_DATA_MISMATCH', 'report_data'],
    ['expected_qe_vendor_id_hex', quote.header.qeVendorId, 'QE_VENDOR_ID_MISMATCH', 'qe_vendor_id'],
  ];

  for (const [field, got, code, label] of pins) {
    const expected = policyString(policy, field);
    if (!expectedHexMatches(expected, got)) {
      return [code, `${label} ${bytesToHex(got)} != policy expected ${expected?.trim().toLowerCase()}`];
    }
  }

  const allowlist = policy.expected_mrseam_allowlist;
  if (Array.isArray(allowlist) && allowlist.length > 0) {
    const got = bytesToHex(quote.body.mrSeam);
    if (!allowlist.some(entry => typeof entry === 'string' && entry.trim().toLowerCase() === got)) {
      return ['MR_SEAM_NOT_ALLOWED', `mr_seam ${got} not in policy allowlist (${allowlist.length} entries)`];
    }
  }

  if (policy.enforce_spec_defaults === true) {
    const tdAttrs = bytesToLittleEndianBigInt(quote.body.tdAttributes);
    const tdAttrDebug = 1n << 0n;
    const tdAttrFixed0 = (1n << 0n) | (1n << 28n) | (1n << 30n) | (1n << 63n);
    if (tdAttrs & tdAttrDebug) {
      return ['TD_ATTRIBUTES_DEBUG_SET', `TD Attributes DEBUG bit is set (td_attributes=${bytesToHex(quote.body.tdAttributes)})`];
    }
    if (tdAttrs & ~tdAttrFixed0) {
      return ['TD_ATTRIBUTES_RESERVED_BIT_SET', `TD Attributes has bit(s) outside FIXED0 set (td_attributes=${bytesToHex(quote.body.tdAttributes)})`];
    }

    const xfam = bytesToLittleEndianBigInt(quote.body.xfam);
    const xfamFixed1 = 0x3n;
    const xfamFixed0 = 0x6DBE7n;
    if ((xfam & xfamFixed1) !== xfamFixed1) {
      return ['XFAM_REQUIRED_BIT_CLEAR', `XFAM required bits 0 (FP) + 1 (SSE) not both set (xfam=${bytesToHex(quote.body.xfam)})`];
    }
    if (xfam & ~xfamFixed0) {
      return ['XFAM_FORBIDDEN_BIT_SET', `XFAM has bit(s) outside FIXED0 set (xfam=${bytesToHex(quote.body.xfam)})`];
    }
  }

  const minTeeTcbSvn = policyString(policy, 'min_tee_tcb_svn_hex');
  if (minTeeTcbSvn && minTeeTcbSvn.trim().length === 32) {
    const minimum = Buffer.from(minTeeTcbSvn.trim(), 'hex');
    for (let i = 0; i < 16; i += 1) {
      if (quote.body.teeTcbSvn[i] < minimum[i]) {
        return [
          'TEE_TCB_SVN_BELOW_MINIMUM',
          `tee_tcb_svn[${i}]=${quote.body.teeTcbSvn[i]} < min[${i}]=${minimum[i]}`,
        ];
      }
    }
  }

  return undefined;
}

function verificationDate(input: JsonRecord): Date {
  const timestamp = input.expiration_check_date_unix;
  if (typeof timestamp === 'number' && Number.isFinite(timestamp)) {
    return new Date(timestamp * 1000);
  }
  return new Date();
}

async function structurallyVerifyQuote(quote: TdxQuote, input: JsonRecord): Promise<PckCertificateChain> {
  const chain = PckCertificateChain.fromPemChain(quote.pckCertChain);
  await chain.verifyChain(verificationDate(input));
  await verifyQuoteSignature(quote);
  await verifyQeReportSignature(quote, chain);
  await verifyQeReportDataBinding(quote);
  return chain;
}

function accepted(quote: TdxQuote): number {
  return emit({
    stage: STAGE,
    accepted: true,
    outputs: {
      quote_version: quote.header.version,
      tee_type: quote.header.teeType === 0x81 ? 'TDX' : `0x${quote.header.teeType.toString(16).padStart(8, '0')}`,
      qv_result: 'OK',
      measurement: {
        type: TDX_GUEST_V2_URI,
        registers: [
          bytesToHex(quote.body.mrTd),
          bytesToHex(quote.body.rtmrs[0]),
          bytesToHex(quote.body.rtmrs[1]),
          bytesToHex(quote.body.rtmrs[2]),
          bytesToHex(quote.body.rtmrs[3]),
        ],
      },
      header_fields: {
        attestation_key_type: quote.header.attestationKeyType,
        qe_vendor_id_hex: bytesToHex(quote.header.qeVendorId),
        user_data_hex: bytesToHex(quote.header.userData),
      },
      body_fields: {
        tee_tcb_svn_hex: bytesToHex(quote.body.teeTcbSvn),
        mrseam_hex: bytesToHex(quote.body.mrSeam),
        mrsignerseam_hex: bytesToHex(quote.body.mrSignerSeam),
        seam_attributes_hex: bytesToHex(quote.body.seamAttributes),
        td_attributes_hex: bytesToHex(quote.body.tdAttributes),
        td_attributes_decoded: decodeTdAttributes(quote.body.tdAttributes),
        xfam_hex: bytesToHex(quote.body.xfam),
        mrtd_hex: bytesToHex(quote.body.mrTd),
        mrconfigid_hex: bytesToHex(quote.body.mrConfigId),
        mrowner_hex: bytesToHex(quote.body.mrOwner),
        mrownerconfig_hex: bytesToHex(quote.body.mrOwnerConfig),
        rtmrs_hex: quote.body.rtmrs.map(bytesToHex),
        report_data_hex: bytesToHex(quote.body.reportData),
      },
    },
  }, EXIT_ACCEPT);
}

async function verifyAttestationTdx(): Promise<number> {
  let input: unknown;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
  } catch (error) {
    return badInput(`input schema violation: ${messageOf(error)}`);
  }
  if (!isRecord(input)) {
    return badInput('input must be a JSON object');
  }
  if (input.schema_version !== '1') {
    return badInput('schema_version must be "1"');
  }
  if (typeof input.quote_b64 !== 'string') {
    return badInput('quote_b64 must be a base64 string');
  }

  const rawQuote = Buffer.from(input.quote_b64, 'base64');
  let quote: TdxQuote;
  try {
    quote = parseTdxQuote(rawQuote);
  } catch (error) {
    const [code, ref] = classifyTdxError(error);
    return reject(code, ref, messageOf(error));
  }

  let chain: PckCertificateChain;
  try {
    chain = await structurallyVerifyQuote(quote, input);
  } catch (error) {
    const [code, ref] = classifyTdxError(error);
    return reject(code, ref, messageOf(error));
  }

  const policy = isRecord(input.policy) ? input.policy : {};
  if (typeof policy.expected_fmspc_hex === 'string') {
    try {
      const extensions = parsePckExtensions(chain.pckLeaf);
      if (extensions.fmspc.toLowerCase() !== policy.expected_fmspc_hex.trim().toLowerCase()) {
        return reject(
          'PCK_FMSPC_MISMATCH',
          '4.7',
          `PCK FMSPC ${extensions.fmspc.toLowerCase()} != policy expected ${policy.expected_fmspc_hex.trim().toLowerCase()}`,
        );
      }
    } catch (error) {
      const [code, ref] = classifyTdxError(error);
      return reject(code, ref, messageOf(error));
    }
  }

  if (policy.tcb_evaluation_required === true) {
    return unsupported('TDX collateral TCB evaluation is not implemented in the JS conformance adapter yet');
  }

  const extendedPolicyFailure = enforceExtendedPolicy(quote, policy);
  if (extendedPolicyFailure) {
    return reject(extendedPolicyFailure[0], '4.8', extendedPolicyFailure[1]);
  }

  return accepted(quote);
}

function capabilities(): number {
  return emit({
    schema_version: '1',
    sdk: 'tinfoil-js',
    sdk_version: '1.1.3-tdx',
    stages_supported: [STAGE],
    platforms_supported: ['tdx'],
    attestation_tdx: {
      supported: true,
      injected_collateral_supported: true,
      verification_time_override: 'supported',
      tcb_evaluation_supported: false,
      public_api_hooks_supported: false,
      accepts_non_terminal_tcb_statuses: false,
      extended_td_checks_supported: true,
      enforces_tcb_evaluation_data_number_minimum: false,
      policy_fields_supported: {
        accepted_qv_results: false,
        expected_fmspc_hex: true,
        expected_td_attributes_hex: true,
        expected_xfam_hex: true,
        expected_mr_signer_seam_hex: true,
        expected_seam_attributes_hex: true,
        expected_mrtd_hex: true,
        expected_mr_config_id_hex: true,
        expected_mr_owner_hex: true,
        expected_mr_owner_config_hex: true,
        expected_rtmr3_hex: true,
        expected_report_data_hex: true,
        expected_qe_vendor_id_hex: true,
        expected_mrseam_allowlist: true,
        enforce_spec_defaults: true,
        min_tee_tcb_svn_hex: true,
      },
    },
  }, EXIT_ACCEPT);
}

async function main(): Promise<number> {
  const command = process.argv[2];
  if (command === 'capabilities') {
    return capabilities();
  }
  if (command === STAGE) {
    return verifyAttestationTdx();
  }
  return badInput(`unknown command: ${command ?? '<missing>'}`);
}

process.exitCode = await main();
