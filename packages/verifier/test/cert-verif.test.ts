import { describe, it, expect } from 'vitest';
import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { ASN1Obj } from '@freedomofpress/crypto-browser';
import { decodeDomains, bytesToHex } from '../src/dcode.js';
import { hashAttestationDocument } from '../src/types.js';
import bundleFixture from './fixtures/attestation-bundle.json';

describe('Certificate Verification', () => {
  it('should extract and decode HPKE key and attestation hash from certificate SANs', async () => {
    const certPem = bundleFixture.enclaveCert;
    console.log('\n=== Certificate Debug ===');
    
    // Parse certificate
    const cert = X509Certificate.parse(certPem);
    console.log('Certificate parsed successfully');
    
    // Extract SANs
    const sanExtension = cert.extension('2.5.29.17');
    expect(sanExtension).toBeDefined();
    console.log('SAN extension found');
    
    const asn1 = ASN1Obj.parseBuffer(sanExtension!.value);
    const sans: string[] = [];
    for (const generalName of asn1.subs) {
      if (generalName.tag.number === 2 && !generalName.tag.constructed) {
        sans.push(new TextDecoder().decode(generalName.value));
      }
    }
    
    console.log('Total SANs:', sans.length);
    
    // Check for HPKE and HATT prefixes
    const hpkeSans = sans.filter(s => s.includes('.hpke.'));
    const hattSans = sans.filter(s => s.includes('.hatt.'));
    
    console.log('HPKE SANs count:', hpkeSans.length);
    console.log('HATT SANs count:', hattSans.length);
    
    expect(hpkeSans.length).toBeGreaterThan(0);
    expect(hattSans.length).toBeGreaterThan(0);
    
    // Decode HPKE key
    const hpkeBytes = decodeDomains(hpkeSans, 'hpke');
    const hpkeHex = bytesToHex(hpkeBytes);
    console.log('Decoded HPKE key (hex):', hpkeHex);
    console.log('HPKE key length:', hpkeBytes.length, 'bytes');
    expect(hpkeBytes.length).toBeGreaterThan(0);
    
    // Decode attestation hash
    const hattBytes = decodeDomains(hattSans, 'hatt');
    const hattString = new TextDecoder().decode(hattBytes);
    console.log('Decoded attestation hash:', hattString);
    console.log('Hash length:', hattString.length, 'chars');
    expect(hattString.length).toBe(64); // SHA-256 hex is 64 chars
    
    // Compute expected hash from attestation document
    const computedHash = await hashAttestationDocument(bundleFixture.enclaveAttestationReport);
    console.log('Computed hash from attestation:', computedHash);
    
    // Verify they match!
    console.log('Hashes match:', hattString === computedHash);
    expect(hattString).toBe(computedHash);
  });
});
