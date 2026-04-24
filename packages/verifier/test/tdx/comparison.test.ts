import { describe, it, expect } from 'vitest';
import { compareMeasurements, measurementFingerprint, PredicateType } from '../../src/types.js';
import { RTMR3_ZERO } from '../../src/tdx/constants.js';
import type { AttestationMeasurement, HardwareMeasurement } from '../../src/types.js';

const SAMPLE_SNP = '33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1';
const SAMPLE_MRTD = '7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114';
const SAMPLE_RTMR0 = '18945fe4f04d952afb91035b74c2527e38458fd972bee01b7ba02004dc0f2fec2ec90825702956cb76f52f5c1d9f5021';
const SAMPLE_RTMR1 = '896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1';
const SAMPLE_RTMR2 = '96a980ecd429079996c94413bc4c4c2bfcf652d626b6daf2a520206ead5065dd53001c2b583a5fbe41921581e25f669c';

describe('Cross-Platform Measurement Comparison', () => {
  describe('Same type', () => {
    it('matches identical TDX measurements', () => {
      const a: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      const b: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      expect(() => compareMeasurements(a, b)).not.toThrow();
    });

    it('rejects differing TDX measurements', () => {
      const a: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      const b: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: ['0000' + SAMPLE_MRTD.slice(4), SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      expect(() => compareMeasurements(a, b)).toThrow('mismatch');
    });

    it('matches identical SEV measurements', () => {
      const a: AttestationMeasurement = {
        type: PredicateType.SevGuestV2,
        registers: [SAMPLE_SNP],
      };
      const b: AttestationMeasurement = {
        type: PredicateType.SevGuestV2,
        registers: [SAMPLE_SNP],
      };
      expect(() => compareMeasurements(a, b)).not.toThrow();
    });

    it('matches identical multi-platform measurements', () => {
      const a: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, SAMPLE_RTMR2],
      };
      const b: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, SAMPLE_RTMR2],
      };
      expect(() => compareMeasurements(a, b)).not.toThrow();
    });
  });

  describe('SnpTdxMultiplatformV1 vs SevGuestV2', () => {
    it('matches when SNP measurement is equal', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, SAMPLE_RTMR2],
      };
      const sev: AttestationMeasurement = {
        type: PredicateType.SevGuestV2,
        registers: [SAMPLE_SNP],
      };
      expect(() => compareMeasurements(multi, sev)).not.toThrow();
      expect(() => compareMeasurements(sev, multi)).not.toThrow();
    });

    it('rejects when SNP measurement differs', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, SAMPLE_RTMR2],
      };
      const sev: AttestationMeasurement = {
        type: PredicateType.SevGuestV2,
        registers: ['0000' + SAMPLE_SNP.slice(4)],
      };
      expect(() => compareMeasurements(multi, sev)).toThrow('mismatch');
      expect(() => compareMeasurements(sev, multi)).toThrow('mismatch');
    });
  });

  describe('SnpTdxMultiplatformV1 vs TdxGuestV2', () => {
    it('matches when RTMR1, RTMR2 match and RTMR3 is zero', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, SAMPLE_RTMR2],
      };
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      expect(() => compareMeasurements(multi, tdx)).not.toThrow();
      expect(() => compareMeasurements(tdx, multi)).not.toThrow();
    });

    it('rejects when RTMR1 differs', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, 'ffff' + SAMPLE_RTMR1.slice(4), SAMPLE_RTMR2],
      };
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      expect(() => compareMeasurements(multi, tdx)).toThrow('RTMR1');
    });

    it('rejects when RTMR2 differs', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, 'ffff' + SAMPLE_RTMR2.slice(4)],
      };
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      expect(() => compareMeasurements(multi, tdx)).toThrow('RTMR2');
    });

    it('rejects when RTMR3 is non-zero', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, SAMPLE_RTMR2],
      };
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, 'ffff' + RTMR3_ZERO.slice(4)],
      };
      expect(() => compareMeasurements(multi, tdx)).toThrow('RTMR3 must be all zeros');
    });

    it('matches Go test: multi-platform TDX v2 match', () => {
      // Exact test case from attestation_test.go TestMeasurementEquals
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: ['sevsnp', 'rtmr1', 'rtmr2'],
      };
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2', RTMR3_ZERO],
      };
      expect(() => compareMeasurements(multi, tdx)).not.toThrow();
    });
  });

  describe('Incompatible types', () => {
    it('rejects TdxGuestV2 vs SevGuestV2 directly', () => {
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      const sev: AttestationMeasurement = {
        type: PredicateType.SevGuestV2,
        registers: [SAMPLE_SNP],
      };
      expect(() => compareMeasurements(tdx, sev)).toThrow('Incompatible measurement types');
      expect(() => compareMeasurements(sev, tdx)).toThrow('Incompatible measurement types');
    });
  });

  describe('Edge cases', () => {
    it('rejects multi-platform with fewer than 3 registers vs TDX', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP],
      };
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
      };
      expect(() => compareMeasurements(multi, tdx)).toThrow('at least 3 registers');
    });

    it('rejects TDX with fewer than 5 registers', () => {
      const multi: AttestationMeasurement = {
        type: PredicateType.SnpTdxMultiplatformV1,
        registers: [SAMPLE_SNP, SAMPLE_RTMR1, SAMPLE_RTMR2],
      };
      const tdx: AttestationMeasurement = {
        type: PredicateType.TdxGuestV2,
        registers: [SAMPLE_MRTD, SAMPLE_RTMR0],
      };
      expect(() => compareMeasurements(multi, tdx)).toThrow('5 registers');
    });
  });
});

describe('Measurement Fingerprint', () => {
  it('returns single register directly for SEV', async () => {
    const m: AttestationMeasurement = {
      type: PredicateType.SevGuestV2,
      registers: [SAMPLE_SNP],
    };
    expect(await measurementFingerprint(m)).toBe(SAMPLE_SNP);
  });

  it('computes SHA-256 hash for multi-register TDX measurement', async () => {
    const m: AttestationMeasurement = {
      type: PredicateType.TdxGuestV2,
      registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
    };
    const fp = await measurementFingerprint(m);
    // Should be a hex SHA-256 hash (64 chars)
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    // Should not equal any single register
    expect(fp).not.toBe(SAMPLE_MRTD);
  });

  it('includes type in multi-register fingerprint', async () => {
    const tdx: AttestationMeasurement = {
      type: PredicateType.TdxGuestV2,
      registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
    };
    const multi: AttestationMeasurement = {
      type: PredicateType.SnpTdxMultiplatformV1,
      registers: [SAMPLE_MRTD, SAMPLE_RTMR0, SAMPLE_RTMR1, SAMPLE_RTMR2, RTMR3_ZERO],
    };
    const fpTdx = await measurementFingerprint(tdx);
    const fpMulti = await measurementFingerprint(multi);
    // Different types with same registers should produce different fingerprints
    expect(fpTdx).not.toBe(fpMulti);
  });

  it('computes SHA-256 hash for multi-platform measurement', async () => {
    const routerMp: AttestationMeasurement = {
      type: PredicateType.SnpTdxMultiplatformV1,
      registers: [
        '33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1',
        '896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1',
        'fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec',
      ],
    };
    const fp = await measurementFingerprint(routerMp);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    expect(fp).not.toBe(routerMp.registers[0]);
  });

  it('matches Go fingerprint for TDX measurement', async () => {
    // From Go test TestAttestationFingerprint
    const tdx: AttestationMeasurement = {
      type: PredicateType.TdxGuestV2,
      registers: [
        '7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114',
        '304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81',
        '896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1',
        'fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      ],
    };
    const fp = await measurementFingerprint(tdx);
    expect(fp).toBe('d4c613f1c2919502eee6c8395527086d57e0cf3d7b1c4fda6ba70d421f6a5e08');
  });

  it('matches Go SEV fingerprint (single register = raw value)', async () => {
    const sev: AttestationMeasurement = {
      type: PredicateType.SevGuestV2,
      registers: ['33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1'],
    };
    const fp = await measurementFingerprint(sev);
    expect(fp).toBe('33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1');
  });

  describe('with targetType (matches Go Fingerprint)', () => {
    const routerMp: AttestationMeasurement = {
      type: PredicateType.SnpTdxMultiplatformV1,
      registers: [
        '33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1',
        '896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1',
        'fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec',
      ],
    };

    const tdxEnclave: AttestationMeasurement = {
      type: PredicateType.TdxGuestV2,
      registers: [
        '7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114',
        '304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81',
        '896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1',
        'fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      ],
    };

    const hw: HardwareMeasurement = {
      MRTD: '7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114',
      RTMR0: '304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81',
    };

    it('TDX: source and enclave fingerprints match Go (type URL included, source != enclave)', async () => {
      const sourceFp = await measurementFingerprint(routerMp, hw, PredicateType.TdxGuestV2);
      const enclaveFp = await measurementFingerprint(tdxEnclave, hw, PredicateType.TdxGuestV2);
      expect(sourceFp).toBe('02e628595f1bbd914799fdf0eab30ab954b0dda6ca96fcdbcbc3ff71cad44e40');
      expect(enclaveFp).toBe('d4c613f1c2919502eee6c8395527086d57e0cf3d7b1c4fda6ba70d421f6a5e08');
    });

    it('SEV: source and enclave fingerprints match Go (single register, source == enclave)', async () => {
      const sevEnclave: AttestationMeasurement = {
        type: PredicateType.SevGuestV2,
        registers: ['33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1'],
      };
      const sourceFp = await measurementFingerprint(routerMp, null, PredicateType.SevGuestV2);
      const enclaveFp = await measurementFingerprint(sevEnclave, null, PredicateType.SevGuestV2);
      expect(sourceFp).toBe('33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1');
      expect(enclaveFp).toBe(sourceFp);
    });

    it('TDX: throws when hardware measurement is missing', async () => {
      await expect(measurementFingerprint(routerMp, null, PredicateType.TdxGuestV2))
        .rejects.toThrow('hardware measurement required');
    });
  });
});
