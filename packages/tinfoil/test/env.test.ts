import { describe, it, expect, vi, afterEach } from 'vitest';
import { isRealBrowser } from '../src/env.js';

describe('isRealBrowser', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('server-side runtimes', () => {
    it('should return false for Node.js environment', () => {
      vi.stubGlobal('process', { versions: { node: '20.0.0' } });
      vi.stubGlobal('window', undefined);
      expect(isRealBrowser()).toBe(false);
    });

    it('should return false for Bun environment', () => {
      vi.stubGlobal('process', { versions: { bun: '1.1.45' } });
      vi.stubGlobal('window', undefined);
      expect(isRealBrowser()).toBe(false);
    });

    it('should return false for Bun even with window globals (web compatibility)', () => {
      vi.stubGlobal('process', { versions: { bun: '1.1.45' } });
      vi.stubGlobal('window', { document: {} });
      vi.stubGlobal('navigator', { userAgent: 'Mozilla/5.0' });
      expect(isRealBrowser()).toBe(false);
    });

    it('should return false for Deno environment', () => {
      vi.stubGlobal('process', undefined);
      vi.stubGlobal('Deno', { version: { deno: '1.40.0' } });
      vi.stubGlobal('window', undefined);
      expect(isRealBrowser()).toBe(false);
    });
  });

  describe('edge runtimes', () => {
    it('should return false for Cloudflare Workers (via userAgent)', () => {
      vi.stubGlobal('process', undefined);
      vi.stubGlobal('Deno', undefined);
      vi.stubGlobal('window', undefined);
      vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' });
      vi.stubGlobal('caches', undefined);
      expect(isRealBrowser()).toBe(false);
    });

    it('should return false for Cloudflare Workers (via caches.default)', () => {
      vi.stubGlobal('process', undefined);
      vi.stubGlobal('Deno', undefined);
      vi.stubGlobal('window', undefined);
      vi.stubGlobal('navigator', undefined);
      vi.stubGlobal('caches', { default: {} });
      expect(isRealBrowser()).toBe(false);
    });
  });

  describe('browser environments', () => {
    it('should return true for real browser environment', () => {
      vi.stubGlobal('process', undefined);
      vi.stubGlobal('Deno', undefined);
      vi.stubGlobal('caches', {});
      vi.stubGlobal('window', { document: {} });
      vi.stubGlobal('navigator', { userAgent: 'Mozilla/5.0' });
      expect(isRealBrowser()).toBe(true);
    });

    it('should return false when window exists but no navigator', () => {
      vi.stubGlobal('process', undefined);
      vi.stubGlobal('Deno', undefined);
      vi.stubGlobal('caches', undefined);
      vi.stubGlobal('window', { document: {} });
      vi.stubGlobal('navigator', undefined);
      expect(isRealBrowser()).toBe(false);
    });
  });

  describe('unknown environments', () => {
    it('should return false for unknown environments (safe default)', () => {
      vi.stubGlobal('process', undefined);
      vi.stubGlobal('Deno', undefined);
      vi.stubGlobal('caches', undefined);
      vi.stubGlobal('window', undefined);
      vi.stubGlobal('navigator', undefined);
      expect(isRealBrowser()).toBe(false);
    });
  });
});
