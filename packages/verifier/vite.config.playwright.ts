/// <reference types="vitest" />
import { defineConfig } from "vite";
import { playwright } from "@vitest/browser-playwright";

export default defineConfig({
  test: {
    include: ["**/*.browser.test.ts"],
    exclude: ["**/*.browser.integration.test.ts", "**/node_modules/**"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }, { browser: "webkit" }],
    },
  },
});
