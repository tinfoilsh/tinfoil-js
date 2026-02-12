import { describe, it, expect } from 'vitest';
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

describe('CertificateChain.fromReport', () => {
  const vcekBase64 = bundleFixture.vcek;
  const vcekDer = Uint8Array.from(atob(vcekBase64), c => c.charCodeAt(0));

  it('builds valid chain from report and pre-provided VCEK', async () => {
    const reportBytes = await decompressReport(bundleFixture.enclaveAttestationReport.body);
    const report = new Report(reportBytes);

    const chain = await CertificateChain.fromReport(report, vcekDer);
    expect(chain.vcek).toBeDefined();
    expect(chain.ark).toBeDefined();
    expect(chain.ask).toBeDefined();
  });
});
