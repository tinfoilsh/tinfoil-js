import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { ARK_CERT, ASK_CERT } from '../src/sev/certs.js';
import { CertificateChain } from '../src/sev/cert-chain.js';
import { Report } from '../src/sev/report.js';
import bundleFixture from './fixtures/attestation-bundle.json';

describe('AMD Certificate Chain Verification', () => {
  it('parses ARK certificate correctly', () => {
    const ark = X509Certificate.parse(ARK_CERT);
    expect(ark.version).toBe('v3');
    expect(ark.signatureAlgorithm).toBe('sha384');
  });

  it('parses ASK certificate correctly', () => {
    const ask = X509Certificate.parse(ASK_CERT);
    expect(ask.version).toBe('v3');
    expect(ask.signatureAlgorithm).toBe('sha384');
  });

  it('validates ARK date range', () => {
    const ark = X509Certificate.parse(ARK_CERT);
    const now = new Date();
    expect(ark.validForDate(now)).toBe(true);
  });

  it('validates ASK date range', () => {
    const ask = X509Certificate.parse(ASK_CERT);
    const now = new Date();
    expect(ask.validForDate(now)).toBe(true);
  });

  it('verifies ARK self-signature with RSA-PSS', async () => {
    const ark = X509Certificate.parse(ARK_CERT);
    const selfSigned = await ark.verify();
    expect(selfSigned).toBe(true);
  });

  it('verifies ASK signed by ARK with RSA-PSS', async () => {
    const ark = X509Certificate.parse(ARK_CERT);
    const ask = X509Certificate.parse(ASK_CERT);
    const signedByArk = await ask.verify(ark);
    expect(signedByArk).toBe(true);
  });
});

// Helper to decompress gzipped attestation report
async function decompressReport(base64Gzipped: string): Promise<Uint8Array> {
  const compressed = Uint8Array.from(atob(base64Gzipped), c => c.charCodeAt(0));
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  writer.write(compressed);
  writer.close();
  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

describe('VCEK Caching (Browser)', () => {
  let mockLocalStorage: Map<string, string>;
  let originalWindow: typeof globalThis.window;
  let originalLocalStorage: Storage | undefined;
  let fetchCallCount: number;
  let fetchedUrls: string[];
  let originalFetch: typeof fetch;

  // Real VCEK certificate from bundle fixture
  const vcekBase64 = bundleFixture.vcek;
  const vcekDer = Uint8Array.from(atob(vcekBase64), c => c.charCodeAt(0));

  beforeEach(() => {
    mockLocalStorage = new Map();
    fetchCallCount = 0;
    fetchedUrls = [];
    originalFetch = globalThis.fetch;

    // Save originals
    originalWindow = globalThis.window;
    originalLocalStorage = globalThis.localStorage;

    // Mock localStorage
    const localStorageMock: Storage = {
      getItem: (key: string) => mockLocalStorage.get(key) ?? null,
      setItem: (key: string, value: string) => { mockLocalStorage.set(key, value); },
      removeItem: (key: string) => { mockLocalStorage.delete(key); },
      clear: () => mockLocalStorage.clear(),
      get length() { return mockLocalStorage.size; },
      key: (index: number) => Array.from(mockLocalStorage.keys())[index] ?? null,
    };

    // @ts-expect-error - mocking window for tests
    globalThis.window = { localStorage: localStorageMock };
    // @ts-expect-error - mocking localStorage for tests
    globalThis.localStorage = localStorageMock;

    // Mock fetch to return real VCEK and track calls
    globalThis.fetch = vi.fn(async (url: RequestInfo | URL) => {
      fetchCallCount++;
      fetchedUrls.push(url.toString());
      return new Response(vcekDer, { status: 200 });
    }) as typeof fetch;
  });

  afterEach(() => {
    // Restore originals
    globalThis.window = originalWindow;
    // @ts-expect-error - restoring original
    globalThis.localStorage = originalLocalStorage;
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('caches VCEK - same report called twice fetches only once', async () => {
    // Parse real report from bundle
    const reportBytes = await decompressReport(bundleFixture.enclaveAttestationReport.body);
    const report = new Report(reportBytes);

    // First call - should fetch VCEK
    const chain1 = await CertificateChain.fromReport(report);
    expect(fetchCallCount).toBe(1);
    expect(fetchedUrls.length).toBe(1);
    expect(fetchedUrls[0]).toContain('kds-proxy.tinfoil.sh/vcek');

    // Verify VCEK was cached
    expect(mockLocalStorage.size).toBe(1);

    // Second call with same report - should use cache (no fetch)
    const chain2 = await CertificateChain.fromReport(report);
    expect(fetchCallCount).toBe(1); // Still 1 - cache hit!
    expect(fetchedUrls.length).toBe(1);

    // Both chains should have valid VCEK certificates
    expect(chain1.vcek).toBeDefined();
    expect(chain2.vcek).toBeDefined();
  });

  it('does not fetch when VCEK is pre-provided', async () => {
    // Parse real report from bundle
    const reportBytes = await decompressReport(bundleFixture.enclaveAttestationReport.body);
    const report = new Report(reportBytes);

    // Call with pre-provided VCEK - should NOT fetch
    const chain = await CertificateChain.fromReport(report, vcekDer);
    expect(fetchCallCount).toBe(0); // No fetch!
    expect(mockLocalStorage.size).toBe(0); // No caching needed

    // Chain should still have valid VCEK
    expect(chain.vcek).toBeDefined();
  });

  it('uses cache key based on chip ID and TCB', async () => {
    // Parse real report from bundle
    const reportBytes = await decompressReport(bundleFixture.enclaveAttestationReport.body);
    const report = new Report(reportBytes);

    // First call
    await CertificateChain.fromReport(report);
    expect(fetchCallCount).toBe(1);

    // The cache key should include chip ID and TCB params
    const cacheKey = Array.from(mockLocalStorage.keys())[0];
    expect(cacheKey).toContain('kds-proxy.tinfoil.sh/vcek/v1/Genoa/');
    expect(cacheKey).toContain('blSPL=');
    expect(cacheKey).toContain('teeSPL=');
    expect(cacheKey).toContain('snpSPL=');
    expect(cacheKey).toContain('ucodeSPL=');
  });

  it('retrieves valid certificate from cache on second call', async () => {
    // Parse real report from bundle
    const reportBytes = await decompressReport(bundleFixture.enclaveAttestationReport.body);
    const report = new Report(reportBytes);

    // First call - fetches and caches
    await CertificateChain.fromReport(report);
    expect(fetchCallCount).toBe(1);

    // Verify cache contains base64-encoded VCEK
    const cacheKey = Array.from(mockLocalStorage.keys())[0];
    const cachedValue = mockLocalStorage.get(cacheKey)!;
    
    // Decode cached value and verify it matches original VCEK
    const decodedFromCache = Uint8Array.from(atob(cachedValue), c => c.charCodeAt(0));
    expect(decodedFromCache).toEqual(vcekDer);

    // Second call - uses cache
    const chain = await CertificateChain.fromReport(report);
    expect(fetchCallCount).toBe(1); // Still 1

    // Verify the chain is valid
    expect(chain.vcek).toBeDefined();
    expect(chain.ark).toBeDefined();
    expect(chain.ask).toBeDefined();
  });
});
