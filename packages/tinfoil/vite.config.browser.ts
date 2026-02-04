/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";
import { playwright } from "@vitest/browser-playwright";

export default defineConfig({
  test: {
    include: ["test/*.browser.test.ts"],
    exclude: ["test/*.browser.integration.test.ts"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
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
