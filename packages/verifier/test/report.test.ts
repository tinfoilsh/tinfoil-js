import { describe, it, expect } from 'vitest';
import { Report } from '../src/sev/report.js';

describe('Report Parsing', () => {
  it('parses version 2 report correctly', () => {
    const base64Data = 'AgAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAHAAAAAAAOSAEAAAAAAAAAAAAAAAAAAAA2NTA4M2U1OTA0YzAyNzNiNjQ0YWQ5MGU1MWUxMmE4ZDc2ZmUwN2YyYWI4YWIxNGQ3NjAxMWIzZTljN2RjYWE3';
    const binaryString = atob(base64Data);
    const testData = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      testData[i] = binaryString.charCodeAt(i);
    }

    const reportBytes = new Uint8Array(0x4a0);
    reportBytes.set(testData, 0);

    const report = new Report(reportBytes);

    expect(report.version).toBe(2);
    expect(report.productName).toBe('Genoa');
  });

  it('rejects invalid report size', () => {
    const tooSmall = new Uint8Array(100);
    expect(() => new Report(tooSmall)).toThrow('smaller than expected SEV-SNP report size');
  });
});
