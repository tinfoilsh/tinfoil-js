import { describe, it, expect } from 'vitest';
import { validateTdxQuote, defaultTdxValidationOptions } from '../../src/tdx/validation.js';
import { parseTdxQuote } from '../../src/tdx/quote.js';
import { base64ToBytes, decompressGzip } from '../../src/attestation.js';
import {
  ACCEPTED_MR_SEAMS,
  ZERO_48,
  DEFAULT_TD_ATTRIBUTES,
  DEFAULT_XFAM,
  DEFAULT_MINIMUM_TEE_TCB_SVN,
} from '../../src/tdx/constants.js';
import { TDX_ATTESTATION_DOC } from './fixtures.js';
import type { TdxQuote } from '../../src/tdx/quote.js';

async function getRealQuote(): Promise<TdxQuote> {
  const compressed = base64ToBytes(TDX_ATTESTATION_DOC.body);
  const raw = await decompressGzip(compressed);
  return parseTdxQuote(raw);
}

describe('TDX Policy Validation', () => {
  it('passes validation with default options on real quote', async () => {
    const quote = await getRealQuote();
    expect(() => validateTdxQuote(quote, defaultTdxValidationOptions)).not.toThrow();
  });

  it('rejects debug mode enabled', async () => {
    const quote = await getRealQuote();
    // Set debug bit (bit 0) in td_attributes
    quote.body.tdAttributes = new Uint8Array([0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00]);
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, tdAttributes: undefined }))
      .toThrow('debug mode is enabled');
  });

  it('rejects disallowed TD attributes bits', async () => {
    const quote = await getRealQuote();
    // Set bit 1 which is not in the allowed set
    quote.body.tdAttributes = new Uint8Array([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, tdAttributes: undefined }))
      .toThrow('disallowed bits set');
  });

  it('rejects non-zero SEAM attributes', async () => {
    const quote = await getRealQuote();
    quote.body.seamAttributes = new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    expect(() => validateTdxQuote(quote)).toThrow('SEAM attributes must be all zeros');
  });

  it('rejects non-zero MR signer SEAM', async () => {
    const quote = await getRealQuote();
    quote.body.mrSignerSeam = new Uint8Array(48);
    quote.body.mrSignerSeam[0] = 0x01;
    expect(() => validateTdxQuote(quote)).toThrow('MR Signer SEAM must be all zeros');
  });

  it('rejects unknown MR_SEAM value', async () => {
    const quote = await getRealQuote();
    quote.body.mrSeam = new Uint8Array(48).fill(0xFF);
    expect(() => validateTdxQuote(quote)).toThrow('does not match any accepted TDX module');
  });

  it('accepts each known MR_SEAM value', async () => {
    const quote = await getRealQuote();
    for (const mrSeam of ACCEPTED_MR_SEAMS) {
      quote.body.mrSeam = new Uint8Array(mrSeam);
      expect(() => validateTdxQuote(quote)).not.toThrow();
    }
  });

  it('rejects TEE TCB SVN below minimum', async () => {
    const quote = await getRealQuote();
    // Set all zeros for TEE TCB SVN (below minimum of 03.01.02....)
    quote.body.teeTcbSvn = new Uint8Array(16);
    expect(() => validateTdxQuote(quote)).toThrow('TEE TCB SVN too low');
  });

  it('accepts TEE TCB SVN at minimum', async () => {
    const quote = await getRealQuote();
    // Set exactly to minimum
    quote.body.teeTcbSvn = new Uint8Array(DEFAULT_MINIMUM_TEE_TCB_SVN);
    expect(() => validateTdxQuote(quote)).not.toThrow();
  });

  it('accepts TEE TCB SVN above minimum', async () => {
    const quote = await getRealQuote();
    const aboveMin = new Uint8Array(DEFAULT_MINIMUM_TEE_TCB_SVN);
    aboveMin[0] = 0xFF; // Way above minimum first byte
    quote.body.teeTcbSvn = aboveMin;
    expect(() => validateTdxQuote(quote)).not.toThrow();
  });

  it('rejects td_attributes mismatch when option set', async () => {
    const quote = await getRealQuote();
    const wrongAttrs = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, tdAttributes: wrongAttrs }))
      .toThrow('TD attributes mismatch');
  });

  it('rejects XFAM mismatch when option set', async () => {
    const quote = await getRealQuote();
    const wrongXfam = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, xfam: wrongXfam }))
      .toThrow('XFAM mismatch');
  });

  it('rejects non-zero mr_config_id when option set', async () => {
    const quote = await getRealQuote();
    const nonZeroConfig = new Uint8Array(48);
    nonZeroConfig[0] = 1;
    quote.body.mrConfigId = nonZeroConfig;
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, mrConfigId: ZERO_48 }))
      .toThrow('MR Config ID mismatch');
  });

  it('rejects non-zero mr_owner when option set', async () => {
    const quote = await getRealQuote();
    const nonZeroOwner = new Uint8Array(48);
    nonZeroOwner[0] = 1;
    quote.body.mrOwner = nonZeroOwner;
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, mrOwner: ZERO_48 }))
      .toThrow('MR Owner mismatch');
  });

  it('rejects non-zero mr_owner_config when option set', async () => {
    const quote = await getRealQuote();
    const nonZeroOwnerConfig = new Uint8Array(48);
    nonZeroOwnerConfig[0] = 1;
    quote.body.mrOwnerConfig = nonZeroOwnerConfig;
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, mrOwnerConfig: ZERO_48 }))
      .toThrow('MR Owner Config mismatch');
  });

  it('skips optional checks when options are undefined', async () => {
    const quote = await getRealQuote();
    expect(() => validateTdxQuote(quote, {})).not.toThrow();
  });

  it('rejects XFAM with missing required FP bit', async () => {
    const quote = await getRealQuote();
    // XFAM with bit 0 (FP) cleared: FP + SSE bits must both be set
    quote.body.xfam = new Uint8Array([0xe6, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00]);
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, xfam: undefined }))
      .toThrow('required bits not set');
  });

  it('rejects XFAM with disallowed bits set', async () => {
    const quote = await getRealQuote();
    // Set bit 24 which is not in XFAM_FIXED0
    quote.body.xfam = new Uint8Array([0xe7, 0x02, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00]);
    expect(() => validateTdxQuote(quote, { ...defaultTdxValidationOptions, xfam: undefined }))
      .toThrow('disallowed bits set');
  });
});
