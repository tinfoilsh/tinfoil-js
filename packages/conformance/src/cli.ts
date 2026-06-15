#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import {
  evaluateCollateral,
  PckCertificateChain,
  PredicateType,
  parsePckExtensions,
  parseTdxQuote,
  verifyAttestation,
  verifyQeReportDataBinding,
  verifyQeReportSignature,
  verifyQuoteSignature,
  type CollateralValidationResult,
  type TdxQuote,
} from '@tinfoilsh/verifier';
import { verifyAttestationSev } from './verify-attestation-sev.js';
import { verifyEhbpKeyBinding } from './verify-ehbp-key-binding.js';
import { verifyFull } from './verify-full.js';
import { verifyHardwareMeasurements } from './verify-hardware-measurements.js';
import { verifyMeasurement } from './verify-measurement.js';
import { verifySigstore } from './verify-sigstore.js';

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

async function runJsonStage(
  handler: (parsed: unknown) => Promise<{ exitCode: number; body: unknown }>,
): Promise<number> {
  let input: unknown;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
  } catch (error) {
    return badInput(`input is not valid JSON: ${messageOf(error)}`);
  }
  const { exitCode, body } = await handler(input);
  return emit(body as JsonRecord, exitCode);
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
  if (
    msg.includes('ak') && (msg.includes('bind') || msg.includes('report data')) ||
    msg.includes('attestation key') && msg.includes('not endorsed')
  ) {
    return ['AK_BINDING_INVALID', '4.5'];
  }
  if (msg.includes('pck crl') && msg.includes('expired')) {
    return ['PCK_CRL_EXPIRED', '4.7.4'];
  }
  if ((msg.includes('root crl') || msg.includes('root ca crl')) && msg.includes('expired')) {
    return ['ROOT_CRL_EXPIRED', '4.7.4'];
  }
  if (msg.includes('tcb info') && (msg.includes('expired') || msg.includes('not yet valid'))) {
    return ['TCB_INFO_EXPIRED', '4.7'];
  }
  if (msg.includes('qe identity') && (msg.includes('expired') || msg.includes('not yet valid'))) {
    return ['QE_IDENTITY_EXPIRED', '4.7'];
  }
  if (msg.includes('tcbevaluationdatanumber') || msg.includes('tcb evaluation data number')) {
    return ['TCB_EVAL_DATA_NUMBER_TOO_LOW', '4.7.11'];
  }
  if (msg.includes('qv result') && msg.includes('not accepted')) {
    return ['QV_RESULT_NOT_ACCEPTED_BY_POLICY', '4.7.7'];
  }
  if (msg.includes('qe identity id invalid')) {
    return ['QE_IDENTITY_ID_INVALID', '4.7.9'];
  }
  if (msg.includes('qe identity version invalid')) {
    return ['QE_IDENTITY_VERSION_INVALID', '4.7.9'];
  }
  if (msg.includes('qe identity') && msg.includes('mrsigner')) {
    return ['QE_IDENTITY_MRSIGNER_MISMATCH', '4.7.9'];
  }
  if (
    msg.includes('qe miscselect') ||
    msg.includes('qe attributes') ||
    msg.includes('isv_prod_id') ||
    msg.includes('isv prod')
  ) {
    return ['QE_IDENTITY_FIELD_MISMATCH', '4.7.9'];
  }
  if (msg.includes('collateral signature verification failed')) {
    return ['QV_RESULT_TERMINAL_UNSPECIFIED', '4.1.2'];
  }
  if (msg.includes('tcb info') && (msg.includes('chain') || msg.includes('certificate') || msg.includes('root'))) {
    return ['TCB_INFO_CHAIN_INVALID', '4.7.3'];
  }
  if (msg.includes('tcb info') && msg.includes('signature')) {
    return ['TCB_INFO_SIGNATURE_INVALID', '4.7'];
  }
  if (msg.includes('qe identity') && msg.includes('signature')) {
    return ['QE_IDENTITY_SIGNATURE_INVALID', '4.7'];
  }
  if (msg.includes('intermediate') && msg.includes('revoked')) {
    return ['INTERMEDIATE_REVOKED', '4.7.4'];
  }
  if (msg.includes('pck') && msg.includes('revoked')) {
    return ['PCK_REVOKED', '4.7.4'];
  }
  if (msg.includes('tcb status') || msg.includes('no matching tcb')) {
    return ['TCB_REVOKED', '4.7.7'];
  }
  if (msg.includes('pck crl') && msg.includes('signature')) {
    return ['PCK_REVOKED', '4.7.4'];
  }
  if (msg.includes('root crl') && msg.includes('signature')) {
    return ['PCK_CHAIN_INVALID', '4.7.4'];
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

function policyStringArray(policy: JsonRecord, field: string): string[] | undefined {
  const value = policy[field];
  return Array.isArray(value) && value.every(item => typeof item === 'string')
    ? value
    : undefined;
}

function recordString(record: JsonRecord, field: string): string | undefined {
  const value = record[field];
  return typeof value === 'string' ? value : undefined;
}

function collateralRecord(input: JsonRecord): JsonRecord {
  return isRecord(input.collateral) ? input.collateral : {};
}

function trustedRootPem(input: JsonRecord): string | undefined {
  return recordString(collateralRecord(input), 'intel_root_ca_pem');
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

function fixtureTextResponse(body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status: 200, headers });
}

function fixtureDerResponse(base64: string | undefined, headers: Record<string, string> = {}): Response {
  if (base64 === undefined) {
    return new Response('missing injected DER collateral', { status: 404 });
  }
  return new Response(Buffer.from(base64, 'base64'), { status: 200, headers });
}

function chainHeader(pem: string | undefined): string | undefined {
  return pem === undefined ? undefined : encodeURIComponent(pem);
}

function headersWith(name: string, value: string | undefined): Record<string, string> {
  return value === undefined ? {} : { [name]: value };
}

function requestUrl(resource: RequestInfo | URL): string {
  if (typeof resource === 'string') {
    return resource;
  }
  if (resource instanceof URL) {
    return resource.toString();
  }
  return resource.url;
}

function fixtureCollateralFetch(input: JsonRecord): typeof fetch {
  const collateral = collateralRecord(input);

  return (async (resource: RequestInfo | URL): Promise<Response> => {
    const url = requestUrl(resource);

    if (url.includes('/qe/identity')) {
      const body = recordString(collateral, 'qe_identity_json');
      if (body === undefined) {
        return new Response('missing injected QE Identity collateral', { status: 404 });
      }
      return fixtureTextResponse(body, headersWith(
        'SGX-Enclave-Identity-Issuer-Chain',
        chainHeader(recordString(collateral, 'qe_identity_issuer_chain_pem')),
      ));
    }

    if (url.includes('/tcb')) {
      const body = recordString(collateral, 'tcb_info_json');
      if (body === undefined) {
        return new Response('missing injected TCB Info collateral', { status: 404 });
      }
      return fixtureTextResponse(body, headersWith(
        'TCB-Info-Issuer-Chain',
        chainHeader(recordString(collateral, 'tcb_info_issuer_chain_pem')),
      ));
    }

    if (url.includes('/pckcrl')) {
      return fixtureDerResponse(recordString(collateral, 'pck_crl_der_b64'), headersWith(
        'SGX-PCK-Crl-Issuer-Chain',
        chainHeader(recordString(collateral, 'pck_crl_issuer_chain_pem')),
      ));
    }

    if (url.includes('IntelSGXRootCA.der')) {
      return fixtureDerResponse(recordString(collateral, 'root_crl_der_b64'));
    }

    return new Response(`no injected collateral for ${url}`, { status: 404 });
  }) as typeof fetch;
}

async function structurallyVerifyQuote(quote: TdxQuote, input: JsonRecord): Promise<PckCertificateChain> {
  const chain = PckCertificateChain.fromPemChain(quote.pckCertChain, trustedRootPem(input));
  await chain.verifyChain(verificationDate(input));
  await verifyQuoteSignature(quote);
  await verifyQeReportSignature(quote, chain);
  await verifyQeReportDataBinding(quote);
  return chain;
}

function accepted(quote: TdxQuote, qvResult: string = 'OK'): number {
  return emit({
    stage: STAGE,
    accepted: true,
    outputs: {
      quote_version: quote.header.version,
      tee_type: quote.header.teeType === 0x81 ? 'TDX' : `0x${quote.header.teeType.toString(16).padStart(8, '0')}`,
      qv_result: qvResult,
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

async function verifyPublicApiTdx(input: JsonRecord, policy: JsonRecord, rawQuote: Buffer): Promise<number> {
  try {
    await verifyAttestation(
      {
        format: PredicateType.TdxGuestV2,
        body: gzipSync(rawQuote).toString('base64'),
      },
      '',
      {
        tdx: {
          proxyHost: '',
          cachePrefetchMs: 0,
          fetch: fixtureCollateralFetch(input),
          trustedRootPem: trustedRootPem(input),
          now: verificationDate(input),
          minTcbEvaluationDataNumber: typeof policy.min_tcb_evaluation_data_number === 'number'
            ? policy.min_tcb_evaluation_data_number
            : 0,
          acceptedQvResults: policyStringArray(policy, 'accepted_qv_results'),
        },
      },
    );
  } catch (error) {
    const [code, ref] = classifyTdxError(error);
    return reject(code, ref, messageOf(error));
  }

  let quote: TdxQuote;
  try {
    quote = parseTdxQuote(rawQuote);
  } catch (error) {
    const [code, ref] = classifyTdxError(error);
    return reject(code, ref, messageOf(error));
  }

  const extendedPolicyFailure = enforceExtendedPolicy(quote, policy);
  if (extendedPolicyFailure) {
    return reject(extendedPolicyFailure[0], '4.8', extendedPolicyFailure[1]);
  }

  return accepted(quote);
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
  const policy = isRecord(input.policy) ? input.policy : {};
  if (input.execution_mode === 'public_api') {
    return verifyPublicApiTdx(input, policy, rawQuote);
  }

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

  let collateralResult: CollateralValidationResult | undefined;
  if (policy.tcb_evaluation_required === true) {
    try {
      const extensions = parsePckExtensions(chain.pckLeaf);
      collateralResult = await evaluateCollateral(
        quote,
        chain,
        extensions,
        {
          proxyHost: '',
          cachePrefetchMs: 0,
          fetch: fixtureCollateralFetch(input),
          trustedRootPem: trustedRootPem(input),
          now: verificationDate(input),
          minTcbEvaluationDataNumber: typeof policy.min_tcb_evaluation_data_number === 'number'
            ? policy.min_tcb_evaluation_data_number
            : 0,
          acceptedQvResults: policyStringArray(policy, 'accepted_qv_results'),
        },
      );
    } catch (error) {
      const [code, ref] = classifyTdxError(error);
      return reject(code, ref, messageOf(error));
    }
  }

  const extendedPolicyFailure = enforceExtendedPolicy(quote, policy);
  if (extendedPolicyFailure) {
    return reject(extendedPolicyFailure[0], '4.8', extendedPolicyFailure[1]);
  }

  return accepted(quote, collateralResult?.qvResult ?? 'OK');
}

function capabilities(): number {
  return emit({
    schema_version: '1',
    sdk: 'tinfoil-js',
    sdk_version: '1.1.3-tdx',
    stages_supported: [
      'verify-sigstore',
      'verify-measurement',
      'verify-hardware-measurements',
      'verify-attestation-sev',
      STAGE,
      'verify-full',
      'verify-ehbp-key-binding',
    ],
    sigstore: {
      trust_root_loading: 'configurable',
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
    },
    measurement: {
      compare_multiplatform_to_tdx_supported: true,
    },
    attestation_sev: {
      supported: true,
      injected_collateral_supported: true,
      extended_checks_supported: true,
      verification_time_override: 'supported',
      amd_root_ca_injection_supported: true,
      // The SEV adapter already calls the verifier's public entrypoint
      // verifyAttestation, so execution_mode=public_api fixtures exercise the
      // public surface through the same path.
      public_api_hooks_supported: true,
    },
    attestation_tdx: {
      supported: true,
      injected_collateral_supported: true,
      verification_time_override: 'supported',
      tcb_evaluation_supported: true,
      public_api_hooks_supported: true,
      accepts_non_terminal_tcb_statuses: true,
      extended_td_checks_supported: true,
      enforces_tcb_evaluation_data_number_minimum: true,
      policy_fields_supported: {
        accepted_qv_results: true,
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
    platforms_supported: ['sev-snp', 'tdx'],
    transport_modes_supported: ['tls-pinning', 'ehbp'],
    flow_modes_supported: ['standard', 'bundle', 'pinned'],
    // SPEC §14.2 EHBP key binding: the transport HPKE key must equal the
    // attested key from report_data[32:64]. The SDK binds by construction
    // (createEncryptedBodyFetch uses only the attested key) and explicitly
    // compares in cert-verify (verifyCertificate).
    ehbp: { key_binding_supported: true },
    known_quirks: {
      'sigstore.dcode_substring_match':
        'cert-verify.ts uses .includes() for .hpke./.hatt. SAN filtering (recon finding, separate fix)',
      'inference.ehbp_unverified_mode_exists':
        'createUnverifiedEncryptedBodyFetch bypasses attestation — must NEVER be used in production',
    },
  }, EXIT_ACCEPT);
}

async function main(): Promise<number> {
  const command = process.argv[2];
  if (command === 'capabilities') {
    return capabilities();
  }
  if (command === 'verify-sigstore') {
    return runJsonStage(verifySigstore);
  }
  if (command === 'verify-measurement') {
    return runJsonStage(verifyMeasurement);
  }
  if (command === 'verify-hardware-measurements') {
    return runJsonStage(verifyHardwareMeasurements);
  }
  if (command === 'verify-attestation-sev') {
    return runJsonStage(verifyAttestationSev);
  }
  if (command === STAGE) {
    return verifyAttestationTdx();
  }
  if (command === 'verify-full') {
    return runJsonStage(verifyFull);
  }
  if (command === 'verify-ehbp-key-binding') {
    return runJsonStage(verifyEhbpKeyBinding);
  }
  return badInput(`unknown command: ${command ?? '<missing>'}`);
}

process.exitCode = await main();
