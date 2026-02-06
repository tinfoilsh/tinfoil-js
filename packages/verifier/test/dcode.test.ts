import { describe, it, expect } from 'vitest';
import { decodeDomains, bytesToHex } from '../src/dcode.js';

describe('dcode decoder', () => {
  describe('decodeDomains', () => {
    it('should decode single-chunk data', () => {
      // Base32 of "test" is "ORSXG5A"
      const domains = ['00orsxg5a.hpke.example.com'];
      const result = decodeDomains(domains, 'hpke');
      expect(new TextDecoder().decode(result)).toBe('test');
    });

    it('should sort chunks by index prefix', () => {
      // Chunks arrive out of order
      const domains = [
        '02g5a.hpke.example.com',
        '00orsx.hpke.example.com',
        '01g5ba.hpke.example.com',
      ];
      const result = decodeDomains(domains, 'hpke');
      expect(result.length).toBeGreaterThan(0);
    });

    it('should filter by prefix', () => {
      const domains = [
        '00orsxg5a.hpke.example.com',  // "test"
        '00jbswy3dp.hatt.example.com', // "Hello"
      ];
      
      const hpkeResult = decodeDomains(domains, 'hpke');
      expect(new TextDecoder().decode(hpkeResult)).toBe('test');
      
      const hattResult = decodeDomains(domains, 'hatt');
      expect(new TextDecoder().decode(hattResult)).toBe('Hello');
    });

    it('should throw if prefix not found', () => {
      const domains = ['00orsxg5a.hpke.example.com'];
      expect(() => decodeDomains(domains, 'missing')).toThrow('Missing expected DNS names with prefix');
    });

    it('should handle case-insensitive base32', () => {
      // Base32 is case-insensitive
      const domains = ['00ORSXG5A.hpke.example.com'];
      const result = decodeDomains(domains, 'hpke');
      expect(new TextDecoder().decode(result)).toBe('test');
    });
  });

  describe('bytesToHex', () => {
    it('should convert empty array', () => {
      expect(bytesToHex(new Uint8Array([]))).toBe('');
    });

    it('should convert bytes to lowercase hex', () => {
      expect(bytesToHex(new Uint8Array([0, 1, 15, 16, 255]))).toBe('00010f10ff');
    });

    it('should pad single digit hex values', () => {
      expect(bytesToHex(new Uint8Array([1, 2, 3]))).toBe('010203');
    });
  });
});
