import { defineConfig } from 'vite';
import { playwright } from '@vitest/browser-playwright';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareCorpus, applyCorrection } from './scripts/corpus.mjs';

const workspace = fileURLToPath(new URL('../..', import.meta.url));
const { paths, vectorRoot } = prepareCorpus();

export default defineConfig({
  plugins: [{
    name: 'conformance-fixtures',
    resolveId(id) { if (id === 'virtual:conformance-fixtures') return '\0conformance-fixtures'; },
    load(id) {
      if (id !== '\0conformance-fixtures') return;
      const fixtures = paths.map((path: string) => {
        return applyCorrection(JSON.parse(readFileSync(resolve(vectorRoot, path), 'utf8')), path);
      });
      return `export default ${JSON.stringify(fixtures)}`;
    },
  }],
  resolve: { alias: { '@tinfoilsh/verifier': fileURLToPath(new URL('../verifier/src/index.ts', import.meta.url)) } },
  test: {
    include: ['test/*.browser.test.ts'],
    reporters: ['default', 'json'],
    outputFile: resolve(workspace, 'artifacts/conformance.browser.json'),
    testTimeout: 30_000,
    browser: {
      enabled: true, headless: true, provider: playwright(),
      instances: [
        { browser: 'chromium' },
        {
          browser: 'webkit',
          provider: playwright({ launchOptions: process.env.TINFOIL_TEST_WEBKIT_EXECUTABLE
            ? { executablePath: process.env.TINFOIL_TEST_WEBKIT_EXECUTABLE } : {} }),
        },
      ],
    },
  },
});
