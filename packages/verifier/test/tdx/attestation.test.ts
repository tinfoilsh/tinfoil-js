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
    expect(result.measurement.registers[0]).toBe(
      '7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114'
    );
    // RTMR0
    expect(result.measurement.registers[1]).toBe(
      '18945fe4f04d952afb91035b74c2527e38458fd972bee01b7ba02004dc0f2fec2ec90825702956cb76f52f5c1d9f5021'
    );
    // RTMR1
    expect(result.measurement.registers[2]).toBe(
      '896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1'
    );
    // RTMR2
    expect(result.measurement.registers[3]).toBe(
      '96a980ecd429079996c94413bc4c4c2bfcf652d626b6daf2a520206ead5065dd53001c2b583a5fbe41921581e25f669c'
    );
    // RTMR3 (all zeros)
    expect(result.measurement.registers[4]).toBe(
      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    );
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
