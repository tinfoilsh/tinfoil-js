import { describe, it, expect } from 'vitest';
import { gunzipSync, gzipSync } from 'node:zlib';
import { Verifier, PINNED_NO_REPO, PINNED_NO_DIGEST } from '../src/client.js';
import { ConfigurationError, AttestationError } from '../src/errors.js';
import { SIGNATURE_OFFSET } from '../src/sev/constants.js';
import { Report } from '../src/sev/report.js';
import { defaultValidationOptions } from '../src/sev/validation.js';
import { PredicateType } from '../src/types.js';
import type { AttestationBundle } from '../src/types.js';
import type { CodeMeasurement } from '../src/pin.js';
import bundleFixture from './fixtures/attestation-bundle.json';

const VALID_REGISTER = 'a'.repeat(96);

/** Returns a register guaranteed to differ from the input while staying valid hex. */
function flipHexNibble(register: string): string {
  return (register[0] === '0' ? '1' : '0') + register.slice(1);
}

/**
 * Pinned-measurement verification: the caller supplies the expected enclave
 * measurement directly and no release provenance is consulted.
 */
describe('Pinned Measurement Verification', () => {
  const bundle: AttestationBundle = bundleFixture as AttestationBundle;

  // Enclave attestation material only: no digest, releaseTag or sigstoreBundle.
  const { digest: _digest, releaseTag: _releaseTag, sigstoreBundle: _sigstoreBundle, ...pinnedBundle } = bundle;

  async function enclaveMeasurement(): Promise<CodeMeasurement> {
    const verifier = new Verifier({ configRepo: 'tinfoilsh/confidential-model-router' });
    const result = await verifier.verifyBundle(bundle);
    return { snp_measurement: result.measurement.registers[0] };
  }

  it('verifies the enclave against a pinned measurement without release provenance', async () => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });

    const result = await verifier.verifyBundle(pinnedBundle);
    expect(result.measurement).toEqual({ type: PredicateType.SevGuestV2, registers: [pinnedMeasurement.snp_measurement] });
    expect(result.hpkePublicKey).toBeTruthy();

    const doc = verifier.getVerificationDocument()!;
    expect(doc.securityVerified).toBe(true);
    expect(doc.configRepo).toBe(PINNED_NO_REPO);
    expect(doc.releaseDigest).toBe(PINNED_NO_DIGEST);
    expect(doc.releaseTag).toBeUndefined();
    expect(doc.codeMeasurement).toEqual(result.measurement);
    expect(doc.codeFingerprint).toBe(doc.enclaveFingerprint);
    expect(doc.steps.fetchDigest.status).toBe('skipped');
    expect(doc.steps.verifyCode.status).toBe('skipped');
    expect(doc.steps.verifyEnclave.status).toBe('success');
    expect(doc.steps.compareMeasurements.status).toBe('success');
    expect(doc.steps.verifyCertificate?.status).toBe('success');
  });

  it('ignores release provenance present in the bundle when pinned', async () => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });

    // A forged digest would fail Sigstore verification in the normal flow.
    await expect(
      verifier.verifyBundle({ ...bundle, digest: 'a'.repeat(64), releaseTag: 'forged-release' })
    ).resolves.toBeDefined();
    expect(verifier.getVerificationDocument()!.releaseDigest).toBe(PINNED_NO_DIGEST);
  });

  it('rejects an enclave whose measurement differs from the pinned one', async () => {
    const actual = await enclaveMeasurement();
    const tampered: CodeMeasurement = {
      snp_measurement: flipHexNibble(actual.snp_measurement),
    };
    const verifier = new Verifier({ pinnedMeasurement: tampered });

    await expect(verifier.verifyBundle(pinnedBundle)).rejects.toThrow(AttestationError);

    const doc = verifier.getVerificationDocument()!;
    expect(doc.securityVerified).toBe(false);
    expect(doc.configRepo).toBe(PINNED_NO_REPO);
    expect(doc.releaseDigest).toBe(PINNED_NO_DIGEST);
    expect(doc.codeMeasurement).toEqual({ type: PredicateType.SevGuestV2, registers: [tampered.snp_measurement] });
    expect(doc.steps.fetchDigest.status).toBe('skipped');
    expect(doc.steps.verifyCode.status).toBe('skipped');
    expect(doc.steps.verifyEnclave.status).toBe('success');
    expect(doc.steps.compareMeasurements.status).toBe('failed');
    expect(doc.steps.compareMeasurements.error).toContain('mismatch');
  });

  it('does not let a pinned measurement mutate after construction', async () => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });
    pinnedMeasurement.snp_measurement = flipHexNibble(pinnedMeasurement.snp_measurement);

    await expect(verifier.verifyBundle(pinnedBundle)).resolves.toBeDefined();
  });

  it('rejects an invalid report signature even when the measurement is pinned', async () => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });
    const reportBytes = gunzipSync(Buffer.from(bundle.enclaveAttestationReport.body, 'base64'));
    reportBytes[SIGNATURE_OFFSET] ^= 1;

    await expect(verifier.verifyBundle({
      ...pinnedBundle,
      enclaveAttestationReport: {
        ...bundle.enclaveAttestationReport,
        body: gzipSync(reportBytes).toString('base64'),
      },
    })).rejects.toThrow('Attestation report signature is invalid');

    const doc = verifier.getVerificationDocument()!;
    expect(doc.securityVerified).toBe(false);
    expect(doc.steps.verifyEnclave.status).toBe('failed');
    expect(doc.steps.compareMeasurements.status).toBe('pending');
    expect(doc.steps.verifyCode.status).toBe('skipped');
  });

  it('enforces report policy even when the measurement is pinned', async () => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });
    const report = new Report(gunzipSync(Buffer.from(bundle.enclaveAttestationReport.body, 'base64')));
    const minimumGuestSvn = defaultValidationOptions.minimumGuestSvn;
    // A stricter policy exercises policy rejection with an authentic signed report.
    defaultValidationOptions.minimumGuestSvn = report.guestSvn + 1;
    try {
      await expect(verifier.verifyBundle(pinnedBundle)).rejects.toThrow('Guest SVN');
      const doc = verifier.getVerificationDocument()!;
      expect(doc.securityVerified).toBe(false);
      expect(doc.steps.verifyEnclave.status).toBe('failed');
      expect(doc.steps.compareMeasurements.status).toBe('pending');
      expect(doc.steps.verifyCode.status).toBe('skipped');
    } finally {
      defaultValidationOptions.minimumGuestSvn = minimumGuestSvn;
    }
  });

  it.each([
    ['invalid certificate', { enclaveCert: '' }, 'Failed to parse enclave TLS certificate'],
    ['wrong certificate domain', { domain: 'wrong.example.com' }, 'Certificate domain mismatch'],
  ] as const)('rejects %s even when the measurement is pinned', async (_name, override, message) => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });

    await expect(verifier.verifyBundle({ ...pinnedBundle, ...override })).rejects.toThrow(message);

    const doc = verifier.getVerificationDocument()!;
    expect(doc.securityVerified).toBe(false);
    expect(doc.steps.verifyEnclave.status).toBe('success');
    expect(doc.steps.compareMeasurements.status).toBe('success');
    expect(doc.steps.verifyCertificate?.status).toBe('failed');
    expect(doc.steps.verifyCode.status).toBe('skipped');
  });

  it('normalizes an uppercase pinned measurement before comparison', async () => {
    const actual = await enclaveMeasurement();
    const verifier = new Verifier({
      pinnedMeasurement: { snp_measurement: actual.snp_measurement.toUpperCase() },
    });

    await expect(verifier.verifyBundle(pinnedBundle)).resolves.toBeDefined();
    expect(verifier.getVerificationDocument()!.codeMeasurement.registers).toEqual([actual.snp_measurement]);
  });

  it('rejects a bundle without release provenance when not pinned', async () => {
    const verifier = new Verifier({ configRepo: 'tinfoilsh/confidential-model-router' });

    // Same error class as any other bad bundle-service material, so
    // SecureClient's retry classification is unchanged from before pinning.
    const rejection = verifier.verifyBundle(pinnedBundle);
    await expect(rejection).rejects.toThrow(AttestationError);
    await expect(rejection).rejects.toThrow('missing release provenance');
    expect(verifier.getVerificationDocument()!.steps.fetchDigest.status).toBe('failed');
    expect(verifier.getVerificationDocument()!.steps.verifyCode.status).toBe('failed');
  });

  it('rejects combining configRepo with pinnedMeasurement', () => {
    expect(() => new Verifier({
      configRepo: 'tinfoilsh/confidential-model-router',
      pinnedMeasurement: { snp_measurement: VALID_REGISTER },
    })).toThrow(ConfigurationError);
  });

  it('rejects a supplied null pin instead of falling back to release verification', () => {
    expect(() => new Verifier({
      configRepo: 'tinfoilsh/confidential-model-router',
      pinnedMeasurement: null as unknown as CodeMeasurement,
    })).toThrow(ConfigurationError);
    expect(() => new Verifier({ pinnedMeasurement: null as unknown as CodeMeasurement })).toThrow(ConfigurationError);
  });

  it.each<[string, unknown]>([
    ['TDX workload', { tdx_measurement: { rtmr1: VALID_REGISTER, rtmr2: VALID_REGISTER } }],
    ['TDX alongside SNP', { snp_measurement: VALID_REGISTER, tdx_measurement: { rtmr1: VALID_REGISTER, rtmr2: VALID_REGISTER } }],
    ['null SNP', { snp_measurement: null }],
    ['non-string SNP', { snp_measurement: 42 }],
    ['short SNP', { snp_measurement: 'abc' }],
    ['non-hex SNP', { snp_measurement: 'g'.repeat(96) }],
    ['empty object', {}],
    ['old register-array format', { type: PredicateType.SevGuestV2, registers: [VALID_REGISTER] }],
  ])('rejects a malformed pin: %s', (_name, pinnedMeasurement) => {
    expect(() => new Verifier({ pinnedMeasurement: pinnedMeasurement as CodeMeasurement })).toThrow(ConfigurationError);
  });
});
