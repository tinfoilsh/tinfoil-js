import { afterEach, describe, expect, it, vi } from 'vitest';
import { gunzipSync } from 'node:zlib';
import { Verifier, PINNED_NO_DIGEST, PINNED_NO_REPO } from '../src/client.js';
import type { VerifiableAttestationBundle } from '../src/client.js';
import { FetchError } from '../src/errors.js';
import { Report } from '../src/sev/report.js';
import { PredicateType } from '../src/types.js';
import type { AttestationBundle } from '../src/types.js';
import bundleFixture from './fixtures/attestation-bundle.json';

const bundle = bundleFixture as AttestationBundle;
const report = new Report(gunzipSync(Buffer.from(bundle.enclaveAttestationReport.body, 'base64')));
const pinnedMeasurement = {
  type: PredicateType.SevGuestV2,
  registers: [Buffer.from(report.measurement).toString('hex')],
};
const CONFIG_REPO = 'tinfoilsh/confidential-model-router';

function mockMaterialFetch(releaseTag?: string, { failRelease = false } = {}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (failRelease && url.pathname.endsWith('/releases/latest')) {
      throw new Error('release lookup unavailable');
    }
    if (url.pathname === '/.well-known/tinfoil-attestation') {
      return Response.json(bundle.enclaveAttestationReport);
    }
    if (url.pathname === '/.well-known/tinfoil-certificate') {
      return Response.json({ certificate: bundle.enclaveCert });
    }
    if (url.pathname.startsWith('/vcek/')) {
      return new Response(Buffer.from(bundle.vcek, 'base64'));
    }
    if (url.pathname.endsWith('/releases/latest')) {
      return Response.json({ tag_name: releaseTag });
    }
    if (url.pathname.endsWith('/tinfoil.hash')) {
      return new Response(bundle.digest);
    }
    if (url.pathname.includes('/attestations/sha256:')) {
      return Response.json({ attestations: [{ bundle: bundle.sigstoreBundle }] });
    }
    throw new Error(`Unexpected fixture request: ${url}`);
  });
  vi.stubGlobal('fetch', fetchMock);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe.each(['release', 'pinned'] as const)('Verifier attempt state (%s)', mode => {
  function createVerifier() {
    return new Verifier({
      serverURL: `https://${bundle.domain}`,
      ...(mode === 'pinned' ? { pinnedMeasurement } : { configRepo: CONFIG_REPO }),
    });
  }

  it.each(['verify', 'verifyBundle'] as const)('detaches the result returned by %s', async method => {
    const verifier = createVerifier();
    await verifier.verifyBundle(bundle);
    mockMaterialFetch(verifier.getVerificationDocument()!.releaseTag);

    const result = method === 'verify'
      ? await verifier.verify()
      : await verifier.verifyBundle(bundle);
    const expected = verifier.getVerificationDocument();
    result.measurement.registers[0] = 'modified';
    result.measurement.type = 'modified';
    result.hpkePublicKey = 'modified';
    result.tlsPublicKeyFingerprint = 'modified';

    expect(verifier.getVerificationDocument()).toEqual(expected);
    expect(expected!.securityVerified).toBe(true);
  });

  it('clears prior success while a new bundle is being verified', async () => {
    const verifier = createVerifier();
    await verifier.verifyBundle(bundle);
    expect(verifier.getVerificationDocument()!.securityVerified).toBe(true);

    const attempt = verifier.verifyBundle(bundle);
    const pending = verifier.getVerificationDocument()!;
    await attempt;
    expect(pending.securityVerified).toBe(false);
    expect(pending.verifiedAt).toBeUndefined();
    expect(pending.steps.verifyEnclave.status).toBe('pending');
    expect(pending.tlsPublicKey).toBe('');
    expect(pending.hpkePublicKey).toBe('');
    expect(verifier.getVerificationDocument()!.securityVerified).toBe(true);
  });

  it('records material-fetch failure after prior success without successful release steps', async () => {
    const verifier = createVerifier();
    await verifier.verifyBundle(bundle);
    expect(verifier.getVerificationDocument()!.securityVerified).toBe(true);
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('material unavailable')));
    vi.useFakeTimers();

    const attempt = verifier.verify();
    const pending = verifier.getVerificationDocument()!;
    const rejection = expect(attempt).rejects.toThrow(FetchError);
    await vi.runAllTimersAsync();
    await rejection;

    expect(pending.securityVerified).toBe(false);
    expect(pending.verifiedAt).toBeUndefined();
    expect(pending.steps.fetchDigest.status).toBe(mode === 'pinned' ? 'skipped' : 'pending');
    expect(pending.steps.verifyCode.status).toBe(mode === 'pinned' ? 'skipped' : 'pending');

    const failed = verifier.getVerificationDocument()!;
    expect(failed.securityVerified).toBe(false);
    expect(failed.verifiedAt).toBeUndefined();
    expect(failed.enclaveHost).toBe(bundle.domain);
    expect(failed.tlsPublicKey).toBe('');
    expect(failed.hpkePublicKey).toBe('');
    // Unreachable enclave material is attributed to the enclave step, matching
    // Go. Every fetch fails here, so the release lookup fails too when not pinned.
    expect(failed.steps.verifyEnclave).toMatchObject({ status: 'failed', error: expect.stringContaining('Network error') });
    expect(failed.steps.otherError).toBeUndefined();
    expect(failed.steps.fetchDigest.status).toBe(mode === 'pinned' ? 'skipped' : 'failed');
    expect(failed.steps.verifyCode.status).toBe(mode === 'pinned' ? 'skipped' : 'pending');
    if (mode === 'pinned') {
      expect(failed.configRepo).toBe(PINNED_NO_REPO);
      expect(failed.releaseDigest).toBe(PINNED_NO_DIGEST);
      expect(failed.codeMeasurement).toEqual(pinnedMeasurement);
    }

    vi.useRealTimers();
    await verifier.verifyBundle(bundle);
    expect(verifier.getVerificationDocument()!.securityVerified).toBe(true);
    expect(verifier.getVerificationDocument()!.steps.otherError).toBeUndefined();
  });

  // No release lookup happens when pinned, so the case only exists for release mode.
  it.skipIf(mode === 'pinned')('attributes a release-lookup failure to fetchDigest and leaves the enclave step untouched', async () => {
    const verifier = createVerifier();
    // Enclave endpoints answer with real fixture material; only the GitHub
    // release lookup fails.
    mockMaterialFetch(bundle.releaseTag, { failRelease: true });
    vi.useFakeTimers();

    const attempt = verifier.verify();
    const rejection = expect(attempt).rejects.toThrow(FetchError);
    await vi.runAllTimersAsync();
    await rejection;

    const failed = verifier.getVerificationDocument()!;
    expect(failed.securityVerified).toBe(false);
    expect(failed.steps.fetchDigest).toMatchObject({ status: 'failed', error: expect.stringContaining('releases/latest') });
    expect(failed.steps.verifyEnclave.status).toBe('pending');
    expect(failed.steps.verifyCode.status).toBe('pending');
    expect(failed.steps.otherError).toBeUndefined();
    vi.useRealTimers();
  });

  it('records a malformed server URL without leaving the document pending', async () => {
    const verifier = new Verifier(mode === 'pinned' ? { pinnedMeasurement, serverURL: 'not a url' } : { configRepo: CONFIG_REPO, serverURL: 'not a url' });

    await expect(verifier.verify()).rejects.toThrow('serverURL must be a valid URL');

    const failed = verifier.getVerificationDocument()!;
    expect(failed.securityVerified).toBe(false);
    expect(failed.steps.otherError).toMatchObject({ status: 'failed', error: expect.stringContaining('valid URL') });
    expect(failed.steps.verifyEnclave.status).toBe('pending');
  });

  it('records an early malformed-bundle failure instead of retaining prior success', async () => {
    const verifier = createVerifier();
    await verifier.verifyBundle(bundle);

    await expect(verifier.verifyBundle(null as unknown as VerifiableAttestationBundle)).rejects.toThrow();

    const failed = verifier.getVerificationDocument()!;
    expect(failed.securityVerified).toBe(false);
    expect(failed.verifiedAt).toBeUndefined();
    expect(failed.steps.otherError?.status).toBe('failed');
    expect(failed.steps.fetchDigest.status).toBe(mode === 'pinned' ? 'skipped' : 'pending');
    expect(failed.steps.verifyCode.status).toBe(mode === 'pinned' ? 'skipped' : 'pending');
  });

  it('clears prior success when verify is called without a server URL', async () => {
    const verifier = new Verifier(mode === 'pinned' ? { pinnedMeasurement } : { configRepo: CONFIG_REPO });
    await verifier.verifyBundle(bundle);

    await expect(verifier.verify()).rejects.toThrow('serverURL is required');

    const failed = verifier.getVerificationDocument()!;
    expect(failed.securityVerified).toBe(false);
    expect(failed.verifiedAt).toBeUndefined();
    expect(failed.steps.otherError).toMatchObject({ status: 'failed', error: expect.stringContaining('serverURL') });
    expect(failed.steps.fetchDigest.status).toBe(mode === 'pinned' ? 'skipped' : 'pending');
  });
});
