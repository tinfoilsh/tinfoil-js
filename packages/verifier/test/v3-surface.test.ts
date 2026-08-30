// Tier-1 v3 surface test (SDK_SURFACE_SPEC.md §1): every name must be
// importable from the package's public entry point.

import { describe, expect, it } from 'vitest';
import {
  fetchAttestation,
  hpkePublicKey,
  NonceSize,
  randomNonce,
  tlsPublicKeyFP,
  VerificationError,
  verifyDocumentV3,
  type RejectionLayer,
  type VerifiedDocumentV3,
} from '../src/index.js';

describe('v3 Tier-1 public surface', () => {
  it('exports the verification functions', () => {
    expect(typeof verifyDocumentV3).toBe('function');
    expect(typeof tlsPublicKeyFP).toBe('function');
    expect(typeof hpkePublicKey).toBe('function');
    expect(typeof fetchAttestation).toBe('function');
    expect(typeof randomNonce).toBe('function');
  });

  it('verifyDocumentV3 is the three-argument public form (no opts seam)', () => {
    // The root/clock override seam is internal (CONFORMANCE_ADAPTER_SPEC §3):
    // the public entry point takes exactly (doc, nonce, repo).
    expect(verifyDocumentV3.length).toBe(3);
  });

  it('exports NonceSize = 32 and the layer-tagged error type', () => {
    expect(NonceSize).toBe(32);
    const layer: RejectionLayer = 'ENVELOPE_REJECTED';
    const err = new VerificationError(layer, 'x');
    expect(err).toBeInstanceOf(Error);
    expect(err.layer).toBe('ENVELOPE_REJECTED');
  });

  it('randomNonce returns fresh NonceSize bytes', () => {
    const n = randomNonce();
    expect(n).toBeInstanceOf(Uint8Array);
    expect(n.length).toBe(NonceSize);
    expect(randomNonce()).not.toEqual(n);
  });

  it('fetchAttestation rejects a wrong-size nonce before dialing', async () => {
    await expect(fetchAttestation('example.com', new Uint8Array(4))).rejects.toThrow(/32 bytes/);
  });

  it('the endorsed-key accessors read a VerifiedDocumentV3', () => {
    const v: VerifiedDocumentV3 = {
      codeDigest: '',
      codeTag: '',
      codeMeasurement: { type: 'snp-tdx-multi-platform-v1', registers: [] },
      enclaveMeasurement: { type: 'snp-tdx-multi-platform-v1', registers: [] },
      cryptoMaterial: [],
    };
    expect(() => tlsPublicKeyFP(v)).toThrow(/crypto material/);
    expect(() => hpkePublicKey(v)).toThrow(/crypto material/);
  });
});
