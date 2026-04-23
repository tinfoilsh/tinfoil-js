import { describe, it, expect } from 'vitest';
import { parseTdxQuote } from '../../src/tdx/quote.js';
import { PckCertificateChain } from '../../src/tdx/cert-chain.js';
import {
  verifyQuoteSignature,
  verifyQeReportSignature,
  verifyQeReportDataBinding,
} from '../../src/tdx/verify.js';
import { base64ToBytes, decompressGzip } from '../../src/attestation.js';
import { TDX_ATTESTATION_DOC } from './fixtures.js';
import type { TdxQuote } from '../../src/tdx/quote.js';

async function getRealQuote(): Promise<TdxQuote> {
  const compressed = base64ToBytes(TDX_ATTESTATION_DOC.body);
  const raw = await decompressGzip(compressed);
  return parseTdxQuote(raw);
}

describe('TDX Quote Signature Verification', () => {
  it('verifies a real quote signature', async () => {
    const quote = await getRealQuote();
    await expect(verifyQuoteSignature(quote)).resolves.toBeUndefined();
  });

  it('rejects a tampered quote body', async () => {
    const quote = await getRealQuote();
    // Tamper with the signed region (modify a byte in the body)
    const tampered = new Uint8Array(quote.signedRegion);
    tampered[100] ^= 0xFF;
    quote.signedRegion = tampered;
    await expect(verifyQuoteSignature(quote)).rejects.toThrow('signature is invalid');
  });

  it('rejects a tampered signature', async () => {
    const quote = await getRealQuote();
    const tampered = new Uint8Array(quote.signature);
    tampered[0] ^= 0xFF;
    quote.signature = tampered;
    await expect(verifyQuoteSignature(quote)).rejects.toThrow();
  });
});

describe('TDX PCK Certificate Chain', () => {
  it('verifies the PCK certificate chain from a real quote', async () => {
    const quote = await getRealQuote();
    const chain = PckCertificateChain.fromPemChain(quote.pckCertChain);
    await expect(chain.verifyChain()).resolves.toBeUndefined();
  });

  it('rejects an empty certificate chain', () => {
    expect(() => PckCertificateChain.fromPemChain([])).toThrow('at least 2 certificates');
  });

  it('rejects a single certificate', () => {
    expect(() => PckCertificateChain.fromPemChain(['-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----']))
      .toThrow();
  });
});

describe('TDX QE Report Signature Verification', () => {
  it('verifies the QE report signature from a real quote', async () => {
    const quote = await getRealQuote();
    const chain = PckCertificateChain.fromPemChain(quote.pckCertChain);
    await chain.verifyChain();
    await expect(verifyQeReportSignature(quote, chain)).resolves.toBeUndefined();
  });

  it('rejects a tampered QE report', async () => {
    const quote = await getRealQuote();
    const chain = PckCertificateChain.fromPemChain(quote.pckCertChain);
    await chain.verifyChain();

    const tampered = new Uint8Array(quote.rawQeReportBytes);
    tampered[50] ^= 0xFF;
    quote.rawQeReportBytes = tampered;
    await expect(verifyQeReportSignature(quote, chain)).rejects.toThrow('QE report signature is invalid');
  });
});

describe('TDX QE Report Data Binding', () => {
  it('verifies the QE report data binding from a real quote', async () => {
    const quote = await getRealQuote();
    await expect(verifyQeReportDataBinding(quote)).resolves.toBeUndefined();
  });

  it('rejects tampered attestation key', async () => {
    const quote = await getRealQuote();
    const tampered = new Uint8Array(quote.attestationKey);
    tampered[0] ^= 0xFF;
    quote.attestationKey = tampered;
    await expect(verifyQeReportDataBinding(quote)).rejects.toThrow('binding verification failed');
  });

  it('rejects tampered QE auth data', async () => {
    const quote = await getRealQuote();
    if (quote.qeAuthData.length > 0) {
      const tampered = new Uint8Array(quote.qeAuthData);
      tampered[0] ^= 0xFF;
      quote.qeAuthData = tampered;
      await expect(verifyQeReportDataBinding(quote)).rejects.toThrow('binding verification failed');
    }
  });
});
