import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Report } from '../src/sev/report.js';

const fixture = JSON.parse(readFileSync(new URL('fixtures/hardware-v3/sev.json', import.meta.url), 'utf8'));
const reportBytes = () => Uint8Array.from(Buffer.from(fixture.report, 'base64'));

describe('SNP report parsing', () => {
  it.each([3, 4, 5])('parses supported report version %s with explicit product identity', version => {
    const bytes = reportBytes();
    new DataView(bytes.buffer).setUint32(0, version, true);
    const report = new Report(bytes);
    expect(report.version).toBe(version);
    expect(report.product).toBe('Genoa');
    expect(report.launch).toBe(fixture.refs.snp.launch);
  });

  it('rejects legacy reports without authenticated CPUID identity', () => {
    const bytes = reportBytes();
    new DataView(bytes.buffer).setUint32(0, 2, true);
    expect(() => new Report(bytes)).toThrow('CPUID report identity required');
  });

  it.each([100, 1183, 1185])('requires exact report size: %s', size => {
    expect(() => new Report(new Uint8Array(size))).toThrow('exactly 1184 bytes');
  });
});
