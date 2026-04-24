import { describe, it, expect } from 'vitest';
import { verifyHardware } from '../../src/hardware.js';
import { PredicateType } from '../../src/types.js';
import type { HardwareMeasurement } from '../../src/types.js';

const measurements: HardwareMeasurement[] = [
  {
    ID: 'alpha@0',
    MRTD: 'abcdef',
    RTMR0: '012345',
  },
  {
    ID: 'beta@1',
    MRTD: 'fedcba',
    RTMR0: '543210',
  },
];

describe('verifyHardware', () => {
  it('TdxGuestV2 successful match', () => {
    const match = verifyHardware(measurements, {
      type: PredicateType.TdxGuestV2,
      registers: ['fedcba', '543210'],
    });
    expect(match.ID).toBe('beta@1');
    expect(match.MRTD).toBe('fedcba');
    expect(match.RTMR0).toBe('543210');
  });

  it('TdxGuestV2 no match found', () => {
    expect(() => verifyHardware(measurements, {
      type: PredicateType.TdxGuestV2,
      registers: ['cccccc', 'dddddd'],
    })).toThrow('no matching hardware platform found');
  });

  it('nil enclave measurement', () => {
    expect(() => verifyHardware(measurements, null)).toThrow('enclave measurement is nil');
  });

  it('undefined enclave measurement', () => {
    expect(() => verifyHardware(measurements, undefined)).toThrow('enclave measurement is nil');
  });

  it('unsupported enclave platform', () => {
    expect(() => verifyHardware(measurements, {
      type: 'unsupported-platform',
      registers: ['abcdef', '012345'],
    })).toThrow('unsupported enclave platform: unsupported-platform');
  });

  it('empty registers', () => {
    expect(() => verifyHardware(measurements, {
      type: PredicateType.TdxGuestV2,
      registers: [],
    })).toThrow('enclave provided fewer registers than expected: 0');
  });

  it('matches first measurement', () => {
    const match = verifyHardware(measurements, {
      type: PredicateType.TdxGuestV2,
      registers: ['abcdef', '012345'],
    });
    expect(match.ID).toBe('alpha@0');
  });

  it('works with extra registers (only checks first two)', () => {
    const match = verifyHardware(measurements, {
      type: PredicateType.TdxGuestV2,
      registers: ['fedcba', '543210', 'extra1', 'extra2', 'extra3'],
    });
    expect(match.ID).toBe('beta@1');
  });
});
