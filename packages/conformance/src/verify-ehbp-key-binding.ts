/**
 * verify-ehbp-key-binding (Tinfoil SPEC §14.2).
 *
 * The EHBP transport HPKE public key MUST equal the attested key carried in
 * report_data[32:64] (report_data layout: [0:32] = TLS SPKI fingerprint,
 * [32:64] = HPKE X25519 public key). A server-offered key that differs is a
 * key swap / MITM and MUST be rejected (fail closed). The EHBP protocol spec
 * alone trusts the /.well-known/hpke-keys endpoint and does not require this
 * binding — it is a Tinfoil-layer requirement.
 *
 * Hermetic — no network. Uses the verifier's real `extractReportDataKeys`
 * (the same [32:64] slice the SEV/TDX verifiers apply) and the real `ehbp`
 * `Identity.fromPublicKeyHex` parser the encrypted transport relies on.
 */

import { extractReportDataKeys } from '@tinfoilsh/verifier';
import { Identity, hexToBytes } from 'ehbp';

const STAGE = 'verify-ehbp-key-binding';

interface VerifyEhbpKeyBindingInput {
  schema_version?: string;
  report_data_hex?: string;
  offered_hpke_public_key_hex?: string;
}

export async function verifyEhbpKeyBinding(
  raw: unknown,
): Promise<{ exitCode: number; body: unknown }> {
  const input = (raw ?? {}) as VerifyEhbpKeyBindingInput;

  if (input.schema_version !== '1') {
    process.stderr.write('input.schema_version != "1"\n');
    return { exitCode: 30, body: { stage: STAGE, accepted: false } };
  }

  // Decode + extract the attested keys via the verifier's real slice.
  let attested: string;
  let tlsFingerprint: string;
  try {
    const reportData = hexToBytes(input.report_data_hex ?? '');
    const keys = extractReportDataKeys(reportData);
    attested = keys.hpkePublicKey;
    tlsFingerprint = keys.tlsPublicKeyFingerprint;
  } catch (e) {
    process.stderr.write(`malformed report_data: ${(e as Error).message}\n`);
    return { exitCode: 30, body: { stage: STAGE, accepted: false } };
  }

  // Validate the offered key through the same EHBP parser the transport uses.
  const offeredHex = input.offered_hpke_public_key_hex ?? '';
  try {
    await Identity.fromPublicKeyHex(offeredHex);
  } catch (e) {
    process.stderr.write(
      `offered hpke key not a valid X25519 public key: ${(e as Error).message}\n`,
    );
    return { exitCode: 30, body: { stage: STAGE, accepted: false } };
  }

  // SPEC §14.2 fail-closed: offered key MUST equal the attested key.
  if (offeredHex.toLowerCase() !== attested.toLowerCase()) {
    return {
      exitCode: 10,
      body: {
        stage: STAGE,
        accepted: false,
        rejection: {
          code: 'EHBP_KEY_BINDING_MISMATCH',
          spec_ref: '14.2',
          message:
            'offered HPKE key does not match the attested key in report_data[32:64]',
        },
      },
    };
  }

  return {
    exitCode: 0,
    body: {
      stage: STAGE,
      accepted: true,
      outputs: {
        attested_hpke_public_key_hex: attested,
        tls_fingerprint_hex: tlsFingerprint,
      },
    },
  };
}
