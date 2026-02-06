/**
 * Certificate verification for enclave TLS certificates.
 * 
 * Verifies that:
 * 1. Certificate is valid for the expected domain
 * 2. Certificate SANs contain the correct HPKE key
 * 3. Certificate SANs contain the correct attestation hash
 */

import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { ASN1Obj } from '@freedomofpress/crypto-browser';
import { decodeDomains, bytesToHex } from './dcode.js';
import { hashAttestationDocument } from './types.js';
import type { AttestationDocument } from './types.js';
import { AttestationError } from './errors.js';

/**
 * Extract DNS names from Subject Alternative Name extension
 * Uses ASN1Obj parser for proper ASN.1 handling
 */
function extractSANs(cert: X509Certificate): string[] {
  // OID 2.5.29.17 = Subject Alternative Name (RFC 5280)
  const sanExtension = cert.extension('2.5.29.17');
  if (!sanExtension) {
    return [];
  }

  const sans: string[] = [];
  const asn1 = ASN1Obj.parseBuffer(sanExtension.value);
  
  // Iterate over GeneralName sequence (RFC 5280 section 4.2.1.6)
  for (const generalName of asn1.subs) {
    // Context-specific tag [2] = dNSName (IA5String)
    if (generalName.tag.number === 2 && !generalName.tag.constructed) {
      sans.push(new TextDecoder().decode(generalName.value));
    }
  }
  
  return sans;
}

/**
 * Get the parent domain (e.g., "sub.example.com" -> "example.com")
 */
function getParentDomain(domain: string): string {
  const parts = domain.split('.');
  if (parts.length <= 2) {
    return domain;
  }
  return parts.slice(1).join('.');
}

/**
 * Check if a domain matches any of the SANs (including wildcards)
 */
function domainMatchesSans(sans: string[], expectedDomain: string): boolean {
  const parentDomain = getParentDomain(expectedDomain);
  
  for (const san of sans) {
    // Exact match
    if (san === expectedDomain) {
      return true;
    }
    // Wildcard match (*.example.com matches sub.example.com, but NOT example.com)
    // Per RFC 6125, wildcards only match a single label, not the apex domain
    if (san.startsWith('*.') && san.substring(2) === parentDomain && expectedDomain !== parentDomain) {
      return true;
    }
  }
  
  return false;
}

export interface CertVerificationResult {
  /** HPKE public key extracted from certificate (hex) */
  hpkePublicKey: string;
  /** Attestation document hash extracted from certificate (hex) */
  attestationHash: string;
  /** DNS names from certificate SANs */
  dnsNames: string[];
}

/**
 * Verify enclave TLS certificate.
 * 
 * @param certPem - PEM-encoded certificate
 * @param expectedDomain - Expected domain name
 * @param attestationDoc - Attestation document to verify hash against
 * @param expectedHpkeKey - Expected HPKE public key (hex)
 * @returns Verification result with extracted values
 * @throws AttestationError if certificate parsing or decoding fails
 * @throws AttestationError if certificate values don't match expected values
 */
export async function verifyCertificate(
  certPem: string,
  expectedDomain: string,
  attestationDoc: AttestationDocument,
  expectedHpkeKey: string
): Promise<CertVerificationResult> {
  // 1. Parse PEM certificate
  let cert: X509Certificate;
  try {
    cert = X509Certificate.parse(certPem);
  } catch (error) {
    throw new AttestationError(
      `Failed to parse enclave TLS certificate: ${(error as Error).message}`,
      { cause: error as Error }
    );
  }

  // 2. Extract SANs
  const sans = extractSANs(cert);
  if (sans.length === 0) {
    throw new AttestationError('Invalid enclave certificate: No Subject Alternative Names found');
  }

  // 3. Verify domain
  if (!domainMatchesSans(sans, expectedDomain)) {
    throw new AttestationError(
      `Certificate domain mismatch: Certificate is not valid for "${expectedDomain}"`
    );
  }

  // 4. Extract and verify HPKE key
  const hpkeSans = sans.filter(s => s.includes('.hpke.'));
  if (hpkeSans.length === 0) {
    throw new AttestationError('Invalid enclave certificate: No HPKE key embedded in Subject Alternative Names');
  }
  
  let hpkeKeyBytes: Uint8Array;
  try {
    hpkeKeyBytes = decodeDomains(hpkeSans, 'hpke');
  } catch (error) {
    throw new AttestationError(
      `Failed to extract HPKE key from certificate: ${(error as Error).message}`,
      { cause: error as Error }
    );
  }
  
  const hpkePublicKey = bytesToHex(hpkeKeyBytes);
  if (hpkePublicKey !== expectedHpkeKey) {
    throw new AttestationError(
      'HPKE key mismatch: The encryption key in the certificate does not match the attested key'
    );
  }

  // 5. Extract and verify attestation hash
  const hattSans = sans.filter(s => s.includes('.hatt.'));
  if (hattSans.length === 0) {
    throw new AttestationError('Invalid enclave certificate: No attestation hash embedded in Subject Alternative Names');
  }
  
  let hashBytes: Uint8Array;
  try {
    hashBytes = decodeDomains(hattSans, 'hatt');
  } catch (error) {
    throw new AttestationError(
      `Failed to extract attestation hash from certificate: ${(error as Error).message}`,
      { cause: error as Error }
    );
  }
  
  // The hash is stored as the hex string bytes
  const certAttestationHash = new TextDecoder().decode(hashBytes);
  const computedHash = await hashAttestationDocument(attestationDoc);
  
  if (certAttestationHash !== computedHash) {
    throw new AttestationError(
      'Attestation hash mismatch: The hash in the certificate does not match the attestation document'
    );
  }

  return {
    hpkePublicKey,
    attestationHash: computedHash,
    dnsNames: sans,
  };
}
