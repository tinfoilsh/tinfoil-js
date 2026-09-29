import { afterEach, describe, expect, it, vi } from 'vitest';
import packageMetadata from '../package.json';
import { fetchAttestationBundle, fetchRouter } from '../src/atc.js';
import { SDK_VERSION } from '../src/version.js';

afterEach(() => vi.restoreAllMocks());

describe('attestation SDK headers', () => {
  it('uses the package version', () => {
    expect(SDK_VERSION).toBe(packageMetadata.version);
  });

  it.each([false, true])('identifies bundle requests, enclave-specific: %s', async (specific) => {
    const payload = {
      domain: 'enclave.example',
      enclaveAttestationReport: { format: 'test', body: 'report' },
      digest: 'digest',
      sigstoreBundle: {},
    };
    const sent: Request[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      sent.push(request);
      return Response.json(request.url.endsWith('/attestation') ? payload : ['enclave.example']);
    });

    const bundle = await fetchAttestationBundle({
      atcBaseUrl: 'https://atc.example',
      ...(specific ? { enclaveURL: 'https://enclave.example', configRepo: 'org/repo' } : {}),
    });
    expect(bundle.enclaveAttestationReport.body).toBe('report');
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe(specific ? 'POST' : 'GET');
    expect(sent[0].headers.get('Tinfoil-SDK')).toBe('tinfoil-js');
    expect(sent[0].headers.get('Tinfoil-SDK-Version')).toBe(packageMetadata.version);
    if (specific) {
      expect(await sent[0].json()).toEqual({ enclaveUrl: 'https://enclave.example', repo: 'org/repo' });
    }

    expect(await fetchRouter('https://atc.example')).toBe('enclave.example');
    expect(sent[1].headers.has('Tinfoil-SDK')).toBe(false);
    expect(sent[1].headers.has('Tinfoil-SDK-Version')).toBe(false);
  });
});
