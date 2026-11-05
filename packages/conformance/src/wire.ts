export const STAGES = [
  'v3-check-envelope',
  'v3-authenticate-provenance',
  'v3-assemble-policy',
  'v3-authenticate-quote',
  'verify-attestation-v3',
] as const;

export type Stage = typeof STAGES[number];
export type RejectionCode = 'ENVELOPE_REJECTED' | 'PROVENANCE_REJECTED' | 'QUOTE_REJECTED' | 'POLICY_REJECTED' | 'MALFORMED_INPUT';
export interface Input {
  schema_version: '1';
  document_b64: string;
  nonce_hex?: string;
  repo?: string;
  amd_root_ca_pem?: string;
  ask_pem?: string;
  intel_sgx_root_pem?: string;
  sigstore_trusted_root_json_b64?: string;
  verification_time_unix?: number;
}
export interface WireMeasurement { type: string; registers: string[] }
export interface Facts {
  code_digest?: string;
  code_measurement?: WireMeasurement;
  enclave_measurement?: WireMeasurement;
  tls_public_key_fp?: string;
  hpke_public_key?: string;
  channel_binding?: 'tls-spki' | 'hpke';
  config?: Record<string, string | number>;
  runtime?: Record<string, string | number>;
  platform?: Record<string, string | number>;
  freshness_expires_at_unix?: number;
}
export interface Output {
  stage: string;
  accepted: boolean;
  outputs?: Facts;
  rejection?: { code: RejectionCode };
}
export interface Verdict { output: Output; exit: 0 | 1 | 10 | 20 | 30; diagnostic?: string }

export function reject(stage: string, code: RejectionCode): Verdict {
  return { exit: code === 'MALFORMED_INPUT' ? 30 : 10, output: { stage, accepted: false, rejection: { code } } };
}
