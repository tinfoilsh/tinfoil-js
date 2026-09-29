import { afterEach, expect, it, vi } from 'vitest';
import packageMetadata from '../package.json';
import { assembleAttestationBundle } from '../src/bundle.js';
import bundleFixture from './fixtures/attestation-bundle.json';

afterEach(() => vi.restoreAllMocks());

it('reports verifier identity only on the enclave attestation request', async () => {
  const sent: Request[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    sent.push(request);
    const url = request.url;
    if (url.endsWith('/.well-known/tinfoil-attestation')) {
      return Response.json(bundleFixture.enclaveAttestationReport);
    }
    if (url.endsWith('/.well-known/tinfoil-certificate')) {
      return Response.json({ certificate: bundleFixture.enclaveCert });
    }
    if (url.endsWith('/releases/latest')) {
      return Response.json({ tag_name: 'v1.2.3' });
    }
    if (url.endsWith('/tinfoil.hash')) {
      return new Response(bundleFixture.digest);
    }
    if (url.includes('/attestations/sha256:')) {
      return Response.json({ attestations: [{ bundle: bundleFixture.sigstoreBundle }] });
    }
    if (url.startsWith('https://kds-proxy.tinfoil.sh/')) {
      return new Response(Uint8Array.from(atob(bundleFixture.vcek), c => c.charCodeAt(0)));
    }
    throw new Error(`Unexpected request: ${url}`);
  });

  const bundle = await assembleAttestationBundle(bundleFixture.domain, 'org/repo');
  expect(bundle.enclaveAttestationReport).toEqual(bundleFixture.enclaveAttestationReport);
  expect(bundle.digest).toBe(bundleFixture.digest);
  expect(bundle.vcek).toBe(bundleFixture.vcek);
  expect(sent).toHaveLength(6);
  for (const request of sent) {
    const isAttestation = new URL(request.url).pathname === '/.well-known/tinfoil-attestation';
    expect(request.headers.get('Tinfoil-SDK')).toBe(isAttestation ? packageMetadata.name : null);
    expect(request.headers.get('Tinfoil-SDK-Version')).toBe(isAttestation ? packageMetadata.version : null);
  }
});
