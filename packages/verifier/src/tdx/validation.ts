import type { TdxQuote } from './quote.js';
import {
  XFAM_FIXED1,
  XFAM_FIXED0,
  TD_ATTRIBUTES_DEBUG,
  TD_ATTRIBUTES_ALLOWED,
  ACCEPTED_MR_SEAMS,
  ZERO_48,
  DEFAULT_TD_ATTRIBUTES,
  DEFAULT_XFAM,
  DEFAULT_MINIMUM_TEE_TCB_SVN,
} from './constants.js';
import { uint8ArrayEqual } from '@freedomofpress/crypto-browser';
import { AttestationError } from '../errors.js';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function littleEndianToU64(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

export interface TdxValidationOptions {
  tdAttributes?: Uint8Array;
  xfam?: Uint8Array;
  minimumTeeTcbSvn?: Uint8Array;
  mrConfigId?: Uint8Array;
  mrOwner?: Uint8Array;
  mrOwnerConfig?: Uint8Array;
  acceptedMrSeams?: Uint8Array[];
}

export const defaultTdxValidationOptions: TdxValidationOptions = {
  tdAttributes: DEFAULT_TD_ATTRIBUTES,
  xfam: DEFAULT_XFAM,
  minimumTeeTcbSvn: DEFAULT_MINIMUM_TEE_TCB_SVN,
  mrConfigId: ZERO_48,
  mrOwner: ZERO_48,
  mrOwnerConfig: ZERO_48,
  acceptedMrSeams: ACCEPTED_MR_SEAMS,
};

function validateXfam(xfamBytes: Uint8Array): void {
  const xfam = littleEndianToU64(xfamBytes);

  if ((xfam & XFAM_FIXED1) !== XFAM_FIXED1) {
    throw new AttestationError(
      `XFAM validation failed: required bits not set. Got 0x${xfam.toString(16)}, ` +
      `bits 0x${XFAM_FIXED1.toString(16)} must be set (FP + SSE)`
    );
  }

  if ((xfam & ~XFAM_FIXED0) !== 0n) {
    throw new AttestationError(
      `XFAM validation failed: disallowed bits set. Got 0x${xfam.toString(16)}, ` +
      `only bits 0x${XFAM_FIXED0.toString(16)} may be set`
    );
  }
}

function validateTdAttributes(tdAttrBytes: Uint8Array): void {
  const tdAttr = littleEndianToU64(tdAttrBytes);

  if ((tdAttr & TD_ATTRIBUTES_DEBUG) !== 0n) {
    throw new AttestationError(
      'TD attributes validation failed: debug mode is enabled. The enclave must have debug disabled for production use'
    );
  }

  if ((tdAttr & ~TD_ATTRIBUTES_ALLOWED) !== 0n) {
    throw new AttestationError(
      `TD attributes validation failed: disallowed bits set. Got 0x${tdAttr.toString(16)}, ` +
      `only bits 0x${TD_ATTRIBUTES_ALLOWED.toString(16)} may be set`
    );
  }
}

function validateSeamAttributes(seamAttr: Uint8Array): void {
  for (let i = 0; i < seamAttr.length; i++) {
    if (seamAttr[i] !== 0) {
      throw new AttestationError(
        `SEAM attributes must be all zeros, got ${bytesToHex(seamAttr)}`
      );
    }
  }
}

function validateMrSignerSeam(mrSignerSeam: Uint8Array): void {
  for (let i = 0; i < mrSignerSeam.length; i++) {
    if (mrSignerSeam[i] !== 0) {
      throw new AttestationError(
        `MR Signer SEAM must be all zeros, got ${bytesToHex(mrSignerSeam)}`
      );
    }
  }
}

function validateMrSeam(mrSeam: Uint8Array, accepted: Uint8Array[]): void {
  for (const accepted_val of accepted) {
    if (uint8ArrayEqual(mrSeam, accepted_val)) {
      return;
    }
  }
  throw new AttestationError(
    `Invalid MR_SEAM: ${bytesToHex(mrSeam)} does not match any accepted TDX module version`
  );
}

function validateMinimumTeeTcbSvn(
  teeTcbSvn: Uint8Array,
  minimum: Uint8Array,
): void {
  if (teeTcbSvn.length !== 16 || minimum.length !== 16) {
    throw new AttestationError(
      `TEE TCB SVN length mismatch: got ${teeTcbSvn.length}, minimum ${minimum.length}, expected 16`
    );
  }

  for (let i = 0; i < 16; i++) {
    if (teeTcbSvn[i] < minimum[i]) {
      throw new AttestationError(
        `TEE TCB SVN too low at byte ${i}: got ${teeTcbSvn[i]}, minimum ${minimum[i]}. ` +
        `Full SVN: ${bytesToHex(teeTcbSvn)}, minimum: ${bytesToHex(minimum)}`
      );
    }
  }
}

export function validateTdxQuote(
  quote: TdxQuote,
  options: TdxValidationOptions = defaultTdxValidationOptions,
): void {
  // Structural checks (from spec section 4.8)
  validateSeamAttributes(quote.body.seamAttributes);
  validateMrSignerSeam(quote.body.mrSignerSeam);
  validateXfam(quote.body.xfam);
  validateTdAttributes(quote.body.tdAttributes);

  // Exact field match checks
  if (options.tdAttributes) {
    if (!uint8ArrayEqual(quote.body.tdAttributes, options.tdAttributes)) {
      throw new AttestationError(
        `TD attributes mismatch: got ${bytesToHex(quote.body.tdAttributes)}, ` +
        `expected ${bytesToHex(options.tdAttributes)}`
      );
    }
  }

  if (options.xfam) {
    if (!uint8ArrayEqual(quote.body.xfam, options.xfam)) {
      throw new AttestationError(
        `XFAM mismatch: got ${bytesToHex(quote.body.xfam)}, expected ${bytesToHex(options.xfam)}`
      );
    }
  }

  if (options.minimumTeeTcbSvn) {
    validateMinimumTeeTcbSvn(quote.body.teeTcbSvn, options.minimumTeeTcbSvn);
  }

  if (options.mrConfigId) {
    if (!uint8ArrayEqual(quote.body.mrConfigId, options.mrConfigId)) {
      throw new AttestationError(
        `MR Config ID mismatch: got ${bytesToHex(quote.body.mrConfigId)}, ` +
        `expected ${bytesToHex(options.mrConfigId)}`
      );
    }
  }

  if (options.mrOwner) {
    if (!uint8ArrayEqual(quote.body.mrOwner, options.mrOwner)) {
      throw new AttestationError(
        `MR Owner mismatch: got ${bytesToHex(quote.body.mrOwner)}, ` +
        `expected ${bytesToHex(options.mrOwner)}`
      );
    }
  }

  if (options.mrOwnerConfig) {
    if (!uint8ArrayEqual(quote.body.mrOwnerConfig, options.mrOwnerConfig)) {
      throw new AttestationError(
        `MR Owner Config mismatch: got ${bytesToHex(quote.body.mrOwnerConfig)}, ` +
        `expected ${bytesToHex(options.mrOwnerConfig)}`
      );
    }
  }

  if (options.acceptedMrSeams) {
    validateMrSeam(quote.body.mrSeam, options.acceptedMrSeams);
  }
}
