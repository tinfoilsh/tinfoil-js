import type { Report } from './report.js';
import type { CertificateChain } from './cert-chain.js';
import { POLICY_RESERVED_1_BIT } from './constants.js';
import { KeyTypes, HashAlgorithms } from '@freedomofpress/crypto-browser';
import { VerificationError, wrapOrThrow } from '../errors.js';

/**
 * Verify the attestation report signature using VCEK's public key.
 *
 * @param vcekPublicKey - The VCEK public key
 * @param report - The attestation report
 * @returns True if signature is valid
 * @throws Error if validation fails
 */
async function verifyReportSignature(
  vcekPublicKey: CryptoKey,
  report: Report
): Promise<boolean> {
  // Validate Report Format
  if (report.version < 2) {
    throw new VerificationError(`Report version is lower than 2: is ${report.version}`);
  }

  // Check reserved bit must be 1
  if (!(report.policy & (1n << BigInt(POLICY_RESERVED_1_BIT)))) {
    throw new VerificationError(`policy[${POLICY_RESERVED_1_BIT}] is reserved, must be 1, got 0`);
  }

  // Check policy bits 63-26 must be zero
  if (report.policy >> 26n) {
    throw new VerificationError('policy bits 63-26 must be zero');
  }  

  // Check signature algorithm must be ECDSA
  if (report.signatureAlgo !== 1) { // 1 = SignEcdsaP384Sha384
    throw new VerificationError(`Unknown SignatureAlgo: ${report.signatureAlgo}`);
  }

  // Convert the signature from AMD's little-endian format to WebCrypto raw format
  // The signature in the report is in raw R||S format in AMD's little-endian format
  // Each component is 72 bytes (0x48) for P384, zero-extended
  // WebCrypto expects raw format: R || S as big-endian, each padded to curve size (48 bytes for P-384)

  // Reverse bytes to convert from little-endian to big-endian
  const rBytesLE = report.signature.slice(0, 0x48);
  const sBytesLE = report.signature.slice(0x48, 0x90);

  const rBytesBE = reverseBytes(rBytesLE);
  const sBytesBE = reverseBytes(sBytesLE);

  // Strip leading zeros and convert to BigInt for normalization
  const r = bytesToBigInt(stripLeadingZeros(rBytesBE));
  const s = bytesToBigInt(stripLeadingZeros(sBytesBE));

  // Convert back to fixed 48-byte arrays (P-384 curve size)
  const rRaw = bigIntToFixedBytes(r, 48);
  const sRaw = bigIntToFixedBytes(s, 48);

  // Create raw signature: R || S
  const rawSignature = new Uint8Array(96);
  rawSignature.set(rRaw, 0);
  rawSignature.set(sRaw, 48);

  // Get the signed data - slice to ensure we have the correct view
  const signedData = report.signedData.slice();

  try {
    const isValid = await crypto.subtle.verify(
      { name: KeyTypes.Ecdsa, hash: HashAlgorithms.SHA384 },
      vcekPublicKey,
      rawSignature,
      signedData
    );

    return isValid;
  } catch (e) {
    wrapOrThrow(e, VerificationError, 'Attestation signature verification failed');
  }
}

/**
 * Verify attestation report with the certificate chain.
 *
 * @param chain - The certificate chain (ARK > ASK > VCEK)
 * @param report - The attestation report
 * @returns True if verification succeeds
 */
export async function verifyAttestation(
  chain: CertificateChain,
  report: Report
): Promise<boolean> {
  // Verify certificate chain
  const isChainValid = await chain.verifyChain();
  if (!isChainValid) {
    throw new VerificationError('Certificate chain verification returned false');
  }

  // Get the CryptoKey from VCEK certificate
  // (EC P-384 key type is validated in validateVcekFormat during chain verification)
  const vcekPublicKey = await chain.vcekPublicKey;
  const isSignatureValid = await verifyReportSignature(vcekPublicKey, report);
  if (!isSignatureValid) {
    throw new VerificationError('Report signature verification returned false');
  }

  return true;
}

/**
 * Reverse the bytes in a bytes array.
 *
 * @param bytes - The bytes array to reverse
 * @returns The reversed bytes array
 */
function reverseBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array([...bytes].reverse());
}

/**
 * Strip leading zeros from a bytes array.
 *
 * @param bytes - The bytes array to strip
 * @returns The bytes array without leading zeros
 */
function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) {
    start++;
  }
  if (start === bytes.length) {
    return new Uint8Array([0]);
  }
  return bytes.slice(start);
}

/**
 * Convert a bytes array to a bigint.
 *
 * @param bytes - The bytes array to convert
 * @returns The bigint
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) {
    return 0n;
  }
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert a bigint to a fixed-size bytes array (big-endian, zero-padded).
 *
 * @param value - The bigint to convert
 * @param size - The desired size in bytes
 * @returns The bytes array
 */
function bigIntToFixedBytes(value: bigint, size: number): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2) {
    hex = '0' + hex;
  }

  const bytes = new Uint8Array(size);
  const hexBytes = hex.length / 2;
  const startOffset = size - hexBytes;

  for (let i = 0; i < hexBytes; i++) {
    bytes[startOffset + i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}
