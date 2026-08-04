import { describe, it, expect } from 'vitest';
import { Verifier } from '../src/client.js';
import type { AttestationBundle } from '../src/types.js';
import bundleFixture from './fixtures/attestation-bundle.json';

/**
 * Tests for verifying attestation bundles.
 * These tests use a hardcoded bundle fetched from https://atc.tinfoil.sh/attestation
 * to ensure the bundle verification flow works correctly.
 */
describe('Bundle Verification', () => {
  // Type the fixture as AttestationBundle
  const bundle: AttestationBundle = bundleFixture as AttestationBundle;

  it('should verify a hardcoded attestation bundle', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    const result = await verifier.verifyBundle(bundle);

    expect(result).toBeDefined();
    expect(result.measurement).toBeDefined();
    expect(result.measurement.type).toBeTruthy();
    expect(result.measurement.registers).toBeInstanceOf(Array);
    expect(result.measurement.registers.length).toBeGreaterThan(0);
  });

  it('should populate verification document after bundle verification', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    const startedAt = Date.now();
    await verifier.verifyBundle(bundle);
    const doc = verifier.getVerificationDocument();

    expect(doc).toBeDefined();
    expect(doc!.securityVerified).toBe(true);
    expect(doc!.enclaveHost).toBe(bundle.domain);
    expect(doc!.schemaVersion).toBe(1);
    expect(doc!.releaseTag).toBeTruthy();
    expect(doc!.releaseDigest).toBe(bundle.digest);
    expect(doc!.verifier?.name).toBe('@tinfoilsh/verifier');
    expect(doc!.verifier?.version).toBeTruthy();
    expect(Date.parse(doc!.verifiedAt!)).toBeGreaterThanOrEqual(startedAt);
    expect(Date.parse(doc!.verifiedAt!)).toBeLessThanOrEqual(Date.now());
    expect(doc!.steps.fetchDigest.status).toBe('success');
    expect(doc!.steps.verifyCode.status).toBe('success');
    expect(doc!.steps.verifyEnclave.status).toBe('success');
    expect(doc!.steps.compareMeasurements.status).toBe('success');
    expect(doc!.steps.verifyCertificate?.status).toBe('success');
  });

  it('should reject a selected release tag that differs from signed provenance', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await expect(
      verifier.verifyBundle({ ...bundle, releaseTag: 'forged-release' })
    ).rejects.toThrow('Release tag mismatch');
  });

  it('should reject an empty selected release tag', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await expect(
      verifier.verifyBundle({ ...bundle, releaseTag: '' })
    ).rejects.toThrow('Release tag mismatch');
  });

  it('should return deeply cloned verification document snapshots', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await verifier.verifyBundle(bundle);
    const original = verifier.getVerificationDocument()!;
    const snapshot = verifier.getVerificationDocument()!;
    snapshot.securityVerified = false;
    snapshot.releaseTag = 'modified';
    snapshot.verifier!.name = 'modified';
    snapshot.steps.verifyCode.status = 'failed';
    snapshot.codeMeasurement.registers[0] = 'modified';
    snapshot.enclaveMeasurement.measurement.registers[0] = 'modified';

    expect(verifier.getVerificationDocument()).toEqual(original);
  });

  it('should verify certificate containing HPKE key and attestation hash', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    const result = await verifier.verifyBundle(bundle);
    const doc = verifier.getVerificationDocument();

    // Certificate verification should have run and succeeded
    expect(doc!.steps.verifyCertificate).toBeDefined();
    expect(doc!.steps.verifyCertificate!.status).toBe('success');

    // HPKE key from attestation should match what's in the certificate
    expect(result.hpkePublicKey).toBeDefined();
    expect(result.hpkePublicKey!.length).toBeGreaterThan(0);
  });

  it('should fail verification with tampered certificate', async () => {
    const tamperedBundle: AttestationBundle = {
      ...bundle,
      // Replace certificate with a different one (wrong HPKE key/attestation hash)
      enclaveCert: bundle.enclaveCert.replace('MII', 'XXX'),
    };

    const verifier = new Verifier({
      serverURL: `https://${tamperedBundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await expect(verifier.verifyBundle(tamperedBundle)).rejects.toThrow();
    expect(verifier.getVerificationDocument()?.verifiedAt).toBeUndefined();
  });

  it('should return TLS and HPKE public keys from bundle verification', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    const result = await verifier.verifyBundle(bundle);

    // TLS fingerprint may or may not be present depending on attestation
    if (result.tlsPublicKeyFingerprint) {
      expect(result.tlsPublicKeyFingerprint).toMatch(/^[0-9a-f]+$/i);
    }

    // HPKE public key should be present
    expect(result.hpkePublicKey).toBeDefined();
    expect(result.hpkePublicKey!.length).toBeGreaterThan(0);
  });

  it('should compute fingerprints from bundle verification', async () => {
    const verifier = new Verifier({
      serverURL: `https://${bundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await verifier.verifyBundle(bundle);
    const doc = verifier.getVerificationDocument();

    expect(doc!.codeFingerprint).toBeTruthy();
    expect(doc!.enclaveFingerprint).toBeTruthy();
    expect(doc!.releaseDigest).toBe(bundle.digest);
  });

  it('should fail verification with tampered digest', async () => {
    const tamperedBundle: AttestationBundle = {
      ...bundle,
      digest: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    };

    const verifier = new Verifier({
      serverURL: `https://${tamperedBundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await expect(verifier.verifyBundle(tamperedBundle)).rejects.toThrow();
  });

  it('should fail verification with tampered attestation report', async () => {
    const tamperedBundle: AttestationBundle = {
      ...bundle,
      enclaveAttestationReport: {
        ...bundle.enclaveAttestationReport,
        body: 'H4sIAAAAAAAA/invalidbase64data==',
      },
    };

    const verifier = new Verifier({
      serverURL: `https://${tamperedBundle.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await expect(verifier.verifyBundle(tamperedBundle)).rejects.toThrow();
  });

  it('should fail verification when enclaveCert is empty', async () => {
    const bundleWithBadCert = {
      ...bundle,
      enclaveCert: '',
    };

    const verifier = new Verifier({
      serverURL: `https://${bundleWithBadCert.domain}`,
      configRepo: 'tinfoilsh/confidential-model-router',
    });

    await expect(verifier.verifyBundle(bundleWithBadCert)).rejects.toThrow();
  });
});
