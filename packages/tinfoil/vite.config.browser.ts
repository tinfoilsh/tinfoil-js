/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";
import { playwright } from "@vitest/browser-playwright";

export default defineConfig({
  optimizeDeps: {
    include: ["openai"],
  },
  test: {
    include: ["test/*.browser.test.ts", "test/v3/*.browser.test.ts"],
    exclude: ["test/*.browser.integration.test.ts"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }, { browser: "webkit" }],
    },
  },
  resolve: {
    alias: [
      { find: 'tinfoil', replacement: resolve(__dirname, 'src/index.browser.ts') },
      // The v3 modules the package's browser field maps, resolved the same way from source.
      { find: /^(.*\/v3\/internal\/platform)\.js$/, replacement: '$1.browser.ts' },
      { find: /^(.*\/v3\/internal\/cachesecret-store)\.js$/, replacement: '$1.browser.ts' },
      { find: /^(.*\/v3\/internal\/transport\/tls)\.js$/, replacement: '$1.browser.ts' },
    ],
  },
});
