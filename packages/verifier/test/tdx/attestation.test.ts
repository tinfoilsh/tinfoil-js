import { describe, it, expect } from 'vitest';
import { verifyAttestation } from '../../src/attestation.js';
import { PredicateType } from '../../src/types.js';
import { TDX_ATTESTATION_DOC, TDX_EXPECTED } from './fixtures.js';

describe('TDX End-to-End Attestation Verification', () => {
  it('verifies a real TDX attestation document', async () => {
    const result = await verifyAttestation(
      { format: PredicateType.TdxGuestV2, body: TDX_ATTESTATION_DOC.body },
      '' // No VCEK for TDX
    );

    expect(result.measurement.type).toBe(PredicateType.TdxGuestV2);
    expect(result.measurement.registers).toHaveLength(5);
    expect(result.measurement.registers).toEqual(TDX_EXPECTED.registers);
    expect(result.tlsPublicKeyFingerprint).toBe(TDX_EXPECTED.tlsPublicKeyFP);
    expect(result.hpkePublicKey).toBe(TDX_EXPECTED.hpkePublicKey);
  });

  it('matches Go implementation output exactly', async () => {
    const result = await verifyAttestation(
      { format: PredicateType.TdxGuestV2, body: TDX_ATTESTATION_DOC.body },
      ''
    );

    // MRTD
    expect(result.measurement.registers[0]).toBe(TDX_EXPECTED.registers[0]);
    // RTMR0
    expect(result.measurement.registers[1]).toBe(TDX_EXPECTED.registers[1]);
    // RTMR1
    expect(result.measurement.registers[2]).toBe(TDX_EXPECTED.registers[2]);
    // RTMR2
    expect(result.measurement.registers[3]).toBe(TDX_EXPECTED.registers[3]);
    // RTMR3 (all zeros)
    expect(result.measurement.registers[4]).toBe(TDX_EXPECTED.registers[4]);
  });

  it('rejects unsupported format', async () => {
    await expect(
      verifyAttestation({ format: 'https://unknown/format' as PredicateType, body: 'dGVzdA==' }, '')
    ).rejects.toThrow('Unsupported attestation document format');
  });

  it('rejects invalid base64 body', async () => {
    await expect(
      verifyAttestation({ format: PredicateType.TdxGuestV2, body: 'not-valid-base64!!!' }, '')
    ).rejects.toThrow();
  });

  it('rejects tampered attestation body', async () => {
    // Modify a character in the base64 body to corrupt the data
    const body = TDX_ATTESTATION_DOC.body;
    const tamperedBody = body.substring(0, 100) + 'X' + body.substring(101);
    await expect(
      verifyAttestation({ format: PredicateType.TdxGuestV2, body: tamperedBody }, '')
    ).rejects.toThrow();
  });
});
