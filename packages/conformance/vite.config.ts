import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: { '@tinfoilsh/verifier': fileURLToPath(new URL('../verifier/src/index.ts', import.meta.url)) },
  },
  test: { include: ['test/*.test.ts'], exclude: ['test/*.browser.test.ts'], testTimeout: 30_000 },
});
