import { describe, it, expect } from 'vitest';
import { gunzipSync, gzipSync } from 'node:zlib';
import { Verifier, PINNED_NO_REPO, PINNED_NO_DIGEST } from '../src/client.js';
import { ConfigurationError, AttestationError } from '../src/errors.js';
import { SIGNATURE_OFFSET } from '../src/sev/constants.js';
import { Report } from '../src/sev/report.js';
import { defaultValidationOptions } from '../src/sev/validation.js';
import { PredicateType } from '../src/types.js';
import type { AttestationBundle, AttestationMeasurement } from '../src/types.js';
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

  async function enclaveMeasurement(): Promise<AttestationMeasurement> {
    const verifier = new Verifier({ configRepo: 'tinfoilsh/confidential-model-router' });
    const result = await verifier.verifyBundle(bundle);
    return result.measurement;
  }

  it('verifies the enclave against a pinned measurement without release provenance', async () => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });

    const result = await verifier.verifyBundle(pinnedBundle);
    expect(result.measurement).toEqual(pinnedMeasurement);
    expect(result.hpkePublicKey).toBeTruthy();

    const doc = verifier.getVerificationDocument()!;
    expect(doc.securityVerified).toBe(true);
    expect(doc.configRepo).toBe(PINNED_NO_REPO);
    expect(doc.releaseDigest).toBe(PINNED_NO_DIGEST);
    expect(doc.releaseTag).toBeUndefined();
    expect(doc.codeMeasurement).toEqual(pinnedMeasurement);
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
    const tampered: AttestationMeasurement = {
      type: actual.type,
      registers: [flipHexNibble(actual.registers[0]), ...actual.registers.slice(1)],
    };
    const verifier = new Verifier({ pinnedMeasurement: tampered });

    await expect(verifier.verifyBundle(pinnedBundle)).rejects.toThrow(AttestationError);

    const doc = verifier.getVerificationDocument()!;
    expect(doc.securityVerified).toBe(false);
    expect(doc.configRepo).toBe(PINNED_NO_REPO);
    expect(doc.releaseDigest).toBe(PINNED_NO_DIGEST);
    expect(doc.codeMeasurement).toEqual(tampered);
    expect(doc.steps.fetchDigest.status).toBe('skipped');
    expect(doc.steps.verifyCode.status).toBe('skipped');
    expect(doc.steps.verifyEnclave.status).toBe('success');
    expect(doc.steps.compareMeasurements.status).toBe('failed');
    expect(doc.steps.compareMeasurements.error).toContain('mismatch');
  });

  it('does not let a pinned measurement mutate after construction', async () => {
    const pinnedMeasurement = await enclaveMeasurement();
    const verifier = new Verifier({ pinnedMeasurement });
    pinnedMeasurement.registers[0] = flipHexNibble(pinnedMeasurement.registers[0]);
    pinnedMeasurement.type = 'tampered';

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
      pinnedMeasurement: { type: actual.type, registers: actual.registers.map(r => r.toUpperCase()) },
    });

    await expect(verifier.verifyBundle(pinnedBundle)).resolves.toBeDefined();
    expect(verifier.getVerificationDocument()!.codeMeasurement.registers).toEqual(actual.registers);
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
      pinnedMeasurement: { type: PredicateType.SevGuestV2, registers: [VALID_REGISTER] },
    })).toThrow(ConfigurationError);
  });

  it('rejects a supplied null pin instead of falling back to release verification', () => {
    expect(() => new Verifier({
      configRepo: 'tinfoilsh/confidential-model-router',
      pinnedMeasurement: null as unknown as AttestationMeasurement,
    })).toThrow(ConfigurationError);
    expect(() => new Verifier({ pinnedMeasurement: null as unknown as AttestationMeasurement })).toThrow(ConfigurationError);
  });

  it.each<[string, unknown]>([
    ['empty object', {}],
    ['missing type', { registers: [VALID_REGISTER] }],
    ['empty type', { type: '', registers: [VALID_REGISTER] }],
    ['inherited property name', { type: 'constructor', registers: [VALID_REGISTER] }],
    ['TDX type', { type: 'https://tinfoil.sh/predicate/tdx-guest/v2', registers: [VALID_REGISTER, VALID_REGISTER, VALID_REGISTER, VALID_REGISTER, VALID_REGISTER] }],
    // This verifier compares only the SNP register, so a multi-platform pin
    // would carry registers that are never enforced.
    ['multiplatform type', { type: PredicateType.SnpTdxMultiplatformV1, registers: [VALID_REGISTER, VALID_REGISTER, VALID_REGISTER] }],
    ['missing registers', { type: PredicateType.SevGuestV2 }],
    ['registers not an array', { type: PredicateType.SevGuestV2, registers: VALID_REGISTER }],
    ['no registers', { type: PredicateType.SevGuestV2, registers: [] }],
    ['too many SEV registers', { type: PredicateType.SevGuestV2, registers: [VALID_REGISTER, VALID_REGISTER] }],
    ['sparse register array', { type: PredicateType.SevGuestV2, registers: new Array(1) }],
    ['short register', { type: PredicateType.SevGuestV2, registers: ['abc'] }],
    ['non-hex register', { type: PredicateType.SevGuestV2, registers: ['g'.repeat(96)] }],
    ['non-string register', { type: PredicateType.SevGuestV2, registers: [42] }],
  ])('rejects a malformed pin: %s', (_name, pinnedMeasurement) => {
    expect(() => new Verifier({ pinnedMeasurement: pinnedMeasurement as AttestationMeasurement })).toThrow(ConfigurationError);
  });
});
