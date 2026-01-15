/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  test: {
    include: ["test/*.browser.test.ts"],
    exclude: ["test/*.browser.integration.test.ts"],
    browser: {
      enabled: true,
      provider: "playwright",
      headless: true,
      instances: [{ browser: "chromium" }],
    },
  },
  resolve: {
    alias: {
      'tinfoil': resolve(__dirname, 'src/index.browser.ts'),
    },
  },
});
