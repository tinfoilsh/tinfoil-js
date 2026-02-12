import { describe, it, expect } from 'vitest';
import { Verifier } from '../src/client.js';
import { assembleAttestationBundle } from '../src/bundle.js';

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === 'true';

describe('Node.js Integration Tests', () => {
  describe('assembleAttestationBundle', () => {
    it.skipIf(!RUN_INTEGRATION)('should assemble a complete bundle from inference.tinfoil.sh', async () => {
      const bundle = await assembleAttestationBundle(
        'inference.tinfoil.sh',
        'tinfoilsh/confidential-model-router',
      );

      expect(bundle.domain).toBe('inference.tinfoil.sh');
      expect(bundle.enclaveAttestationReport).toBeDefined();
      expect(bundle.enclaveAttestationReport.format).toBeTruthy();
      expect(bundle.enclaveAttestationReport.body).toBeTruthy();
      expect(bundle.digest).toMatch(/^[0-9a-f]{64}$/);
      expect(bundle.sigstoreBundle).toBeDefined();
      expect(bundle.vcek).toBeTruthy();
      expect(bundle.enclaveCert).toBeTruthy();
      expect(bundle.enclaveCert).toContain('BEGIN CERTIFICATE');
    }, 60000);
  });

  describe('Verifier against inference.tinfoil.sh', () => {
    it.skipIf(!RUN_INTEGRATION)('should verify enclave with serverURL set to inference.tinfoil.sh', async () => {
      const verifier = new Verifier({
        serverURL: 'https://inference.tinfoil.sh',
        configRepo: 'tinfoilsh/confidential-model-router',
      });

      const result = await verifier.verify();

      expect(result).toBeDefined();
      expect(result.measurement).toBeDefined();
      expect(result.measurement.type).toBeTruthy();
      expect(result.measurement.registers).toBeInstanceOf(Array);
      expect(result.measurement.registers.length).toBeGreaterThan(0);

      const doc = verifier.getVerificationDocument();
      expect(doc).toBeDefined();
      expect(doc!.securityVerified).toBe(true);
      expect(doc!.enclaveHost).toBe('inference.tinfoil.sh');
      expect(doc!.steps.fetchDigest.status).toBe('success');
      expect(doc!.steps.verifyCode.status).toBe('success');
      expect(doc!.steps.verifyEnclave.status).toBe('success');
      expect(doc!.steps.compareMeasurements.status).toBe('success');
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)('should return TLS public key fingerprint', async () => {
      const verifier = new Verifier({
        serverURL: 'https://inference.tinfoil.sh',
        configRepo: 'tinfoilsh/confidential-model-router',
      });

      const result = await verifier.verify();

      expect(result.tlsPublicKeyFingerprint).toBeDefined();
      expect(result.tlsPublicKeyFingerprint).toMatch(/^[0-9a-f]+$/i);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)('should return HPKE public key', async () => {
      const verifier = new Verifier({
        serverURL: 'https://inference.tinfoil.sh',
        configRepo: 'tinfoilsh/confidential-model-router',
      });

      const result = await verifier.verify();

      expect(result.hpkePublicKey).toBeDefined();
      expect(result.hpkePublicKey!.length).toBeGreaterThan(0);
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)('should populate verification document fingerprints', async () => {
      const verifier = new Verifier({
        serverURL: 'https://inference.tinfoil.sh',
        configRepo: 'tinfoilsh/confidential-model-router',
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc!.codeFingerprint).toBeTruthy();
      expect(doc!.enclaveFingerprint).toBeTruthy();
      expect(doc!.releaseDigest).toBeTruthy();
      expect(doc!.tlsPublicKey).toBeTruthy();
    }, 60000);

    it.skipIf(!RUN_INTEGRATION)('should use provided config repo', async () => {
      const verifier = new Verifier({
        serverURL: 'https://inference.tinfoil.sh',
        configRepo: 'tinfoilsh/confidential-model-router',
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc!.configRepo).toBe('tinfoilsh/confidential-model-router');
    }, 60000);
  });
});
