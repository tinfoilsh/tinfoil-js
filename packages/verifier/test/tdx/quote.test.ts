import { describe, it, expect } from 'vitest';
import { parseTdxQuote } from '../../src/tdx/quote.js';
import { base64ToBytes, decompressGzip } from '../../src/attestation.js';
import {
  TDX_QUOTE_VERSION,
  TDX_ATTESTATION_KEY_TYPE,
  TDX_TEE_TYPE,
  INTEL_QE_VENDOR_ID,
  RTMR_COUNT,
} from '../../src/tdx/constants.js';
import { TDX_ATTESTATION_DOC, TDX_EXPECTED } from './fixtures.js';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function decompressFixture(): Promise<Uint8Array> {
  const compressed = base64ToBytes(TDX_ATTESTATION_DOC.body);
  return decompressGzip(compressed);
}

describe('TDX Quote Parsing', () => {
  it('parses a real TDX quote correctly', async () => {
    const rawQuote = await decompressFixture();
    const quote = parseTdxQuote(rawQuote);

    // Header validation
    expect(quote.header.version).toBe(TDX_QUOTE_VERSION);
    expect(quote.header.attestationKeyType).toBe(TDX_ATTESTATION_KEY_TYPE);
    expect(quote.header.teeType).toBe(TDX_TEE_TYPE);
    expect(bytesToHex(quote.header.qeVendorId)).toBe(bytesToHex(INTEL_QE_VENDOR_ID));

    // Body field sizes
    expect(quote.body.teeTcbSvn.length).toBe(16);
    expect(quote.body.mrSeam.length).toBe(48);
    expect(quote.body.mrSignerSeam.length).toBe(48);
    expect(quote.body.seamAttributes.length).toBe(8);
    expect(quote.body.tdAttributes.length).toBe(8);
    expect(quote.body.xfam.length).toBe(8);
    expect(quote.body.mrTd.length).toBe(48);
    expect(quote.body.mrConfigId.length).toBe(48);
    expect(quote.body.mrOwner.length).toBe(48);
    expect(quote.body.mrOwnerConfig.length).toBe(48);
    expect(quote.body.reportData.length).toBe(64);
    expect(quote.body.rtmrs.length).toBe(RTMR_COUNT);

    // RTMR sizes
    for (const rtmr of quote.body.rtmrs) {
      expect(rtmr.length).toBe(48);
    }

    // Signed region should be 632 bytes
    expect(quote.signedRegion.length).toBe(632);

    // Signature and key sizes
    expect(quote.signature.length).toBe(64);
    expect(quote.attestationKey.length).toBe(64);

    // QE report
    expect(quote.rawQeReportBytes.length).toBe(384);
    expect(quote.qeReport.cpuSvn.length).toBe(16);
    expect(quote.qeReport.attributes.length).toBe(16);
    expect(quote.qeReport.mrEnclave.length).toBe(32);
    expect(quote.qeReport.mrSigner.length).toBe(32);
    expect(quote.qeReport.reportData.length).toBe(64);
    expect(quote.qeReportSignature.length).toBe(64);

    // PCK cert chain should have at least 2 certs
    expect(quote.pckCertChain.length).toBeGreaterThanOrEqual(2);
    for (const pem of quote.pckCertChain) {
      expect(pem).toContain('-----BEGIN CERTIFICATE-----');
      expect(pem).toContain('-----END CERTIFICATE-----');
    }
  });

  it('extracts correct measurement registers', async () => {
    const rawQuote = await decompressFixture();
    const quote = parseTdxQuote(rawQuote);

    expect(bytesToHex(quote.body.mrTd)).toBe(TDX_EXPECTED.registers[0]);
    expect(bytesToHex(quote.body.rtmrs[0])).toBe(TDX_EXPECTED.registers[1]);
    expect(bytesToHex(quote.body.rtmrs[1])).toBe(TDX_EXPECTED.registers[2]);
    expect(bytesToHex(quote.body.rtmrs[2])).toBe(TDX_EXPECTED.registers[3]);
    expect(bytesToHex(quote.body.rtmrs[3])).toBe(TDX_EXPECTED.registers[4]);
  });

  it('extracts correct report data (TLS key FP + HPKE key)', async () => {
    const rawQuote = await decompressFixture();
    const quote = parseTdxQuote(rawQuote);

    const tlsKeyFp = bytesToHex(quote.body.reportData.slice(0, 32));
    const hpkeKey = bytesToHex(quote.body.reportData.slice(32, 64));

    expect(tlsKeyFp).toBe(TDX_EXPECTED.tlsPublicKeyFP);
    expect(hpkeKey).toBe(TDX_EXPECTED.hpkePublicKey);
  });

  it('rejects quote that is too small', () => {
    const tooSmall = new Uint8Array(100);
    expect(() => parseTdxQuote(tooSmall)).toThrow('too small');
  });

  it('rejects quote with wrong version', async () => {
    const rawQuote = await decompressFixture();
    const modified = new Uint8Array(rawQuote);
    // Set version to 5 (at offset 0x00, uint16 LE)
    modified[0] = 5;
    modified[1] = 0;
    expect(() => parseTdxQuote(modified)).toThrow('version');
  });

  it('rejects quote with wrong TEE type', async () => {
    const rawQuote = await decompressFixture();
    const modified = new Uint8Array(rawQuote);
    // Set tee_type to 0 (at offset 0x04, uint32 LE)
    modified[4] = 0;
    modified[5] = 0;
    modified[6] = 0;
    modified[7] = 0;
    expect(() => parseTdxQuote(modified)).toThrow('TEE type');
  });

  it('rejects quote with wrong attestation key type', async () => {
    const rawQuote = await decompressFixture();
    const modified = new Uint8Array(rawQuote);
    // Set attestation_key_type to 1 (at offset 0x02, uint16 LE)
    modified[2] = 1;
    modified[3] = 0;
    expect(() => parseTdxQuote(modified)).toThrow('attestation key type');
  });

  it('rejects quote with wrong QE vendor ID', async () => {
    const rawQuote = await decompressFixture();
    const modified = new Uint8Array(rawQuote);
    // Corrupt QE vendor ID (at offset 0x0C)
    modified[0x0C] = 0xFF;
    expect(() => parseTdxQuote(modified)).toThrow('QE Vendor ID');
  });
});
