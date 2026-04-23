import type { TdxQuote } from './quote.js';
import type { PckCertificateChain } from './cert-chain.js';
import { AttestationError, wrapOrThrow } from '../errors.js';

async function importEcdsaP256RawKey(rawXY: Uint8Array): Promise<CryptoKey> {
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(rawXY, 1);

  return crypto.subtle.importKey(
    'raw',
    uncompressed,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

async function ecdsaP256Sha256Verify(
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  // Create fresh ArrayBuffer copies to satisfy WebCrypto's BufferSource type
  const sigBuf = new Uint8Array(signature).buffer as ArrayBuffer;
  const dataBuf = new Uint8Array(data).buffer as ArrayBuffer;
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    sigBuf,
    dataBuf,
  );
}

export async function verifyQuoteSignature(quote: TdxQuote): Promise<void> {
  let attestKey: CryptoKey;
  try {
    attestKey = await importEcdsaP256RawKey(quote.attestationKey);
  } catch (e) {
    throw new AttestationError('Failed to import TDX attestation key', { cause: e as Error });
  }

  let valid: boolean;
  try {
    valid = await ecdsaP256Sha256Verify(attestKey, quote.signature, quote.signedRegion);
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'TDX quote signature verification failed');
  }

  if (!valid) {
    throw new AttestationError(
      'TDX quote signature is invalid: the quote was not signed by the attestation key'
    );
  }
}

export async function verifyQeReportSignature(
  quote: TdxQuote,
  chain: PckCertificateChain,
): Promise<void> {
  const pckKey = await chain.pckPublicKey;

  let valid: boolean;
  try {
    valid = await ecdsaP256Sha256Verify(pckKey, quote.qeReportSignature, quote.rawQeReportBytes);
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'QE report signature verification failed');
  }

  if (!valid) {
    throw new AttestationError(
      'QE report signature is invalid: the QE report was not signed by the PCK certificate'
    );
  }
}

export async function verifyQeReportDataBinding(quote: TdxQuote): Promise<void> {
  // expected = SHA-256(attestation_key || qe_auth_data) || zeros(32)
  const bindingInput = new Uint8Array(quote.attestationKey.length + quote.qeAuthData.length);
  bindingInput.set(quote.attestationKey, 0);
  bindingInput.set(quote.qeAuthData, quote.attestationKey.length);

  const hashBuffer = await crypto.subtle.digest('SHA-256', bindingInput);
  const hash = new Uint8Array(hashBuffer);

  const expected = new Uint8Array(64);
  expected.set(hash, 0);

  const actual = quote.qeReport.reportData;
  if (actual.length !== 64) {
    throw new AttestationError(`QE report data has wrong length: ${actual.length}, expected 64`);
  }

  for (let i = 0; i < 64; i++) {
    if (actual[i] !== expected[i]) {
      throw new AttestationError(
        'QE report data binding verification failed: attestation key is not endorsed by the QE'
      );
    }
  }
}
