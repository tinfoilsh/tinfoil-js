import { afterEach, describe, expect, it, vi } from 'vitest';
import * as publicAPI from '@tinfoilsh/verifier';
import { createVerifierForConformance } from '../../verifier/src/client.js';
import { runAdapter, errorVerdict } from '../src/adapter.js';
import fixture from './fixtures/golden-sev.json';

const bytes = (text: string) => Uint8Array.from(Buffer.from(text, 'base64'));
const document = bytes(fixture.input.document_b64);
const nonce = Uint8Array.from(Buffer.from(fixture.input.nonce_hex, 'hex'));
const at = new Date(fixture.input.verification_time_unix * 1000);
const trust = () => ({ sigstoreRoot: JSON.parse(Buffer.from(fixture.input.sigstore_trusted_root_json_b64, 'base64').toString()),
  amdRootPem: fixture.input.ask_pem + '\n' + fixture.input.amd_root_ca_pem });
afterEach(() => vi.unstubAllGlobals());

describe('public offline verification surface', () => {
  it('exports the v3 API and keeps fixture seams and retired v2 APIs private', () => {
    for (const name of ['Verifier', 'Verification', 'verifyDocumentV3', 'verifyDocumentV3At', 'randomNonce',
      'NONCE_SIZE', 'fetchAttestationDocument', 'UsageError', 'VerificationError']) expect(publicAPI).toHaveProperty(name);
    for (const name of ['createVerifierForConformance', 'provenanceOptionsForConformance', 'assembleAttestationBundle', 'AttestationError', 'FetchError']) expect(publicAPI).not.toHaveProperty(name);
    expect(publicAPI.NONCE_SIZE).toBe(32);
    expect(publicAPI.randomNonce()).not.toEqual(publicAPI.randomNonce());
  });
  it('cannot create a successful result from caller data or construction', () => {
    expect(() => Reflect.construct(publicAPI.Verification, [])).toThrow(publicAPI.UsageError);
    const forged = Object.create(publicAPI.Verification.prototype);
    expect(() => forged.cryptoMaterialData('tls', publicAPI.KEY_TLS)).toThrow(publicAPI.UsageError);
    expect(() => new publicAPI.Verifier({ sigstoreRoot: trust().sigstoreRoot } as never)).toThrow(publicAPI.UsageError);
  });
  it('runs the full successful public operation without network access', async () => {
    const forbidden = vi.fn(() => { throw new Error('Offline verification attempted I/O'); });
    vi.stubGlobal('fetch', forbidden);
    const verifier = createVerifierForConformance({}, trust());
    expect(verifier).toBeInstanceOf(publicAPI.Verifier);
    const verified = await verifier.verifyDocumentV3At(document, nonce, fixture.input.repo, at);
    expect(verified.codeDigest).toBe(fixture.expected.code_digest);
    expect(verified.tlsPublicKeyFingerprint()).toBe(fixture.expected.tls_public_key_fp);
    expect(verified.hpkePublicKey()).toBe(fixture.expected.hpke_public_key);
    expect(verified.cryptoMaterialData('absent', publicAPI.KEY_TLS)).toBeUndefined();
    expect(forbidden).not.toHaveBeenCalled();
  });
  it('detaches authenticated results, clocks and trust inputs', async () => {
    const roots = trust(), verifier = createVerifierForConformance({}, roots);
    roots.sigstoreRoot.certificateAuthorities.length = 0;
    const clock = new Date(at);
    const result = await verifier.verifyDocumentV3At(document, nonce, fixture.input.repo, clock);
    clock.setTime(0); result.freshnessExpiresAt!.setTime(0); result.metadata.verifiedAt.setTime(0);
    expect(result.metadata.verifiedAt.getTime()).toBe(at.getTime());
    expect(result.freshnessExpiresAt!.getTime()).toBe(at.getTime() + 7 * 86_400_000);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.cryptoMaterial)).toBe(true);
    expect(Object.isFrozen(result.codeMeasurement)).toBe(true);
    expect(result.cryptoMaterial).not.toBe(result.cryptoMaterial);
  });
  it('keeps concurrent archived times and production roots independent', async () => {
    const verifier = createVerifierForConformance({}, trust());
    const results = await Promise.allSettled([
      verifier.verifyDocumentV3At(document, nonce, fixture.input.repo, at),
      verifier.verifyDocumentV3At(document, nonce, fixture.input.repo, new Date(at.getTime() + 8 * 86_400_000)),
      publicAPI.verifyDocumentV3At(document, nonce, fixture.input.repo, at),
    ]);
    expect(results[0].status).toBe('fulfilled');
    for (const result of results.slice(1)) {
      expect(result.status).toBe('rejected');
      if (result.status === 'rejected') expect(result.reason).toMatchObject({ name: 'VerificationError', layer: 'provenance' });
    }
  });
});

describe('adapter verdict boundaries', () => {
  it('distinguishes malformed adapter input from rejected document bytes', async () => {
    expect((await runAdapter('verify-attestation-v3', { schema_version: '1', document_b64: 'not base64' })).exit).toBe(30);
    const rejected = await runAdapter('verify-attestation-v3', { schema_version: '1', document_b64: 'e30=', nonce_hex: '00'.repeat(32), repo: 'org/repo' });
    expect(rejected.exit).toBe(10); expect(rejected.output.rejection?.code).toBe('ENVELOPE_REJECTED');
  });
  it('rejects unsupported versions, unsafe time values and incomplete trust pairs', async () => {
    for (const update of [{ schema_version: '9' }, { verification_time_unix: 2 ** 60 }, { amd_root_ca_pem: '' }, { nonce_hex: 'A0' }, { unexpected: true }]) {
      expect((await runAdapter(fixture.stage, { ...fixture.input, ...update })).exit).toBe(30);
    }
  });
  it('derives categories only from typed outer errors and reports unknown layers as internal', () => {
    for (const layer of ['envelope', 'provenance', 'quote', 'policy']) {
      const result = errorVerdict('verify-attestation-v3', new publicAPI.VerificationError(layer, 'misleading other error text'));
      expect(result.output.rejection?.code).toBe(layer.toUpperCase() + '_REJECTED');
    }
    expect(errorVerdict('x', new Error('ENVELOPE_REJECTED')).exit).toBe(1);
    expect(errorVerdict('x', new publicAPI.VerificationError('future-layer', 'failure')).exit).toBe(1);
  });
});

it('classifies malformed provenance repository identities as caller input errors', async () => {
  const result = await runAdapter('v3-authenticate-provenance', { ...fixture.input, repo: 'not-a-repo' });
  expect(result).toMatchObject({ exit: 30, output: { accepted: false, rejection: { code: 'MALFORMED_INPUT' } } });
});
