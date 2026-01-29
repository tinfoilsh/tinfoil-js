import { describe, it, expect } from 'vitest';
import { Verifier } from '../src/client.js';
import { compareMeasurements, measurementFingerprint, PredicateType, FormatMismatchError, MeasurementMismatchError } from '../src/types.js';

const DEFAULT_ENCLAVE_URL = 'https://inference.tinfoil.sh';
const DEFAULT_CONFIG_REPO = 'tinfoilsh/confidential-model-router';

describe('Browser Integration Tests', () => {
  describe('Verifier against real enclave', () => {
    it('should verify enclave with provided config repo', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
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
      expect(doc!.steps.fetchDigest.status).toBe('success');
      expect(doc!.steps.verifyCode.status).toBe('success');
      expect(doc!.steps.verifyEnclave.status).toBe('success');
      expect(doc!.steps.compareMeasurements.status).toBe('success');
    }, 30000);

    it('should return TLS public key fingerprint', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      const result = await verifier.verify();

      expect(result.tlsPublicKeyFingerprint).toBeDefined();
      expect(result.tlsPublicKeyFingerprint).toMatch(/^[0-9a-f]+$/i);
    }, 30000);

    it('should return HPKE public key', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      const result = await verifier.verify();

      expect(result.hpkePublicKey).toBeDefined();
      expect(result.hpkePublicKey!.length).toBeGreaterThan(0);
    }, 30000);

    it('should populate verification document fingerprints', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc!.codeFingerprint).toBeTruthy();
      expect(doc!.enclaveFingerprint).toBeTruthy();
      expect(doc!.releaseDigest).toBeTruthy();
      expect(doc!.tlsPublicKey).toBeTruthy();
    }, 30000);

    it('should verify enclave with custom config repo', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: 'tinfoilsh/confidential-model-router'
      });

      const result = await verifier.verify();

      expect(result).toBeDefined();
      expect(result.measurement).toBeDefined();

      const doc = verifier.getVerificationDocument();
      expect(doc).toBeDefined();
      expect(doc!.configRepo).toBe('tinfoilsh/confidential-model-router');
      expect(doc!.securityVerified).toBe(true);
    }, 30000);
  });

  describe('Verification document completeness', () => {
    it('should populate all required fields in verification document', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc).toBeDefined();
      expect(doc!.configRepo).toBeTruthy();
      expect(doc!.enclaveHost).toBeTruthy();
      expect(doc!.releaseDigest).toBeTruthy();
      expect(doc!.codeMeasurement).toBeDefined();
      expect(doc!.codeMeasurement.type).toBeTruthy();
      expect(doc!.codeMeasurement.registers).toBeInstanceOf(Array);
      expect(doc!.enclaveMeasurement).toBeDefined();
      expect(doc!.enclaveMeasurement.measurement).toBeDefined();
      expect(doc!.tlsPublicKey).toBeTruthy();
      expect(doc!.codeFingerprint).toBeTruthy();
      expect(doc!.enclaveFingerprint).toBeTruthy();
      expect(doc!.selectedRouterEndpoint).toBeTruthy();
      expect(doc!.securityVerified).toBe(true);
      expect(doc!.steps).toBeDefined();
    }, 30000);

    it('should have matching code and enclave fingerprints for verified enclave', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc!.codeFingerprint).toBe(doc!.enclaveFingerprint);
    }, 30000);

    it('should have consistent measurement types between code and enclave', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      const codeType = doc!.codeMeasurement.type;
      const enclaveType = doc!.enclaveMeasurement.measurement.type;

      const snpCompatibleTypes = [
        PredicateType.SevGuestV2,
        PredicateType.SnpTdxMultiplatformV1
      ];

      if (codeType === enclaveType) {
        expect(true).toBe(true);
      } else {
        expect(snpCompatibleTypes).toContain(codeType);
        expect(snpCompatibleTypes).toContain(enclaveType);
      }
    }, 30000);
  });

  describe('Measurement operations', () => {
    it('should compute fingerprint for single-register measurement', async () => {
      const measurement = { type: 'sev-snp', registers: ['abc123'] };
      const fingerprint = await measurementFingerprint(measurement);
      expect(fingerprint).toBe('abc123');
    });

    it('should compute SHA-256 fingerprint for multi-register measurement', async () => {
      const measurement = { type: 'sev-snp', registers: ['abc', 'def', 'ghi'] };
      const fingerprint = await measurementFingerprint(measurement);
      expect(fingerprint).toHaveLength(64);
      expect(fingerprint).toMatch(/^[0-9a-f]+$/);
    });

    it('should compare matching measurements successfully', () => {
      const a = { type: 'sev-snp', registers: ['abc123'] };
      const b = { type: 'sev-snp', registers: ['abc123'] };
      expect(() => compareMeasurements(a, b)).not.toThrow();
    });

    it('should throw FormatMismatchError for incompatible types', () => {
      const a = { type: 'sev-snp', registers: ['abc123'] };
      const b = { type: 'tdx-incompatible', registers: ['abc123'] };
      expect(() => compareMeasurements(a, b)).toThrow(FormatMismatchError);
    });

    it('should throw MeasurementMismatchError for different registers', () => {
      const a = { type: 'sev-snp', registers: ['abc123'] };
      const b = { type: 'sev-snp', registers: ['def456'] };
      expect(() => compareMeasurements(a, b)).toThrow(MeasurementMismatchError);
    });

    it('should allow comparison between SNP and multiplatform types', () => {
      const a = { type: PredicateType.SevGuestV2, registers: ['abc123'] };
      const b = { type: PredicateType.SnpTdxMultiplatformV1, registers: ['abc123'] };
      expect(() => compareMeasurements(a, b)).not.toThrow();
    });
  });

  describe('Verification failure handling', () => {
    it('should handle invalid server URL gracefully', async () => {
      const verifier = new Verifier({
        serverURL: 'https://invalid-enclave-that-does-not-exist.tinfoil.sh',
        configRepo: DEFAULT_CONFIG_REPO
      });

      await expect(verifier.verify()).rejects.toThrow();

      // Verification document may be undefined if verification fails before document is created
      const doc = verifier.getVerificationDocument();
      if (doc) {
        expect(doc.securityVerified).toBe(false);
      }
    }, 15000);

    it('should mark verifyEnclave step as failed for unreachable server', async () => {
      const verifier = new Verifier({
        serverURL: 'https://invalid-enclave-that-does-not-exist.tinfoil.sh',
        configRepo: DEFAULT_CONFIG_REPO
      });

      await expect(verifier.verify()).rejects.toThrow();

      // Verification document may be undefined if verification fails early
      const doc = verifier.getVerificationDocument();
      if (doc && doc.steps) {
        expect(doc.steps.verifyEnclave.status).toBe('failed');
        expect(doc.steps.verifyEnclave.error).toBeTruthy();
      }
    }, 15000);

    it('should require serverURL when calling verify()', async () => {
      const verifier = new Verifier({ serverURL: '', configRepo: DEFAULT_CONFIG_REPO });
      await expect(verifier.verify()).rejects.toThrow('serverURL is required');
    });

    it('should require configRepo in constructor', () => {
      expect(() => new Verifier({ serverURL: DEFAULT_ENCLAVE_URL } as any)).toThrow('configRepo is required');
    });
  });

  describe('Verifier instance configuration', () => {
    it('should use provided config repo', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc!.configRepo).toBe('tinfoilsh/confidential-model-router');
    }, 30000);

    it('should extract hostname from serverURL correctly', async () => {
      const verifier = new Verifier({
        serverURL: 'https://inference.tinfoil.sh',
        configRepo: DEFAULT_CONFIG_REPO
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc!.enclaveHost).toBe('inference.tinfoil.sh');
    }, 30000);

    it('should handle serverURL with trailing path', async () => {
      const verifier = new Verifier({
        serverURL: 'https://inference.tinfoil.sh/some/path',
        configRepo: DEFAULT_CONFIG_REPO
      });

      await verifier.verify();
      const doc = verifier.getVerificationDocument();

      expect(doc!.enclaveHost).toBe('inference.tinfoil.sh');
      expect(doc!.securityVerified).toBe(true);
    }, 30000);
  });

  describe('Multiple verification calls', () => {
    it('should allow re-verification with same verifier instance', async () => {
      const verifier = new Verifier({
        serverURL: DEFAULT_ENCLAVE_URL,
        configRepo: DEFAULT_CONFIG_REPO
      });

      const result1 = await verifier.verify();
      expect(result1).toBeDefined();

      const result2 = await verifier.verify();
      expect(result2).toBeDefined();

      expect(result1.measurement.registers).toEqual(result2.measurement.registers);
    }, 60000);
  });
});
