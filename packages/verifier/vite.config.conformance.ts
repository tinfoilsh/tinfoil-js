/// <reference types="vitest" />
import { defineConfig } from "vite";
import { playwright } from "@vitest/browser-playwright";

// Runs the full shared v3 conformance suite (test/v3-conformance.browser.test.ts)
// in real Chromium. Fixtures must be synced first: scripts/sync-v3-fixtures.mjs
// (wired into `npm run test:browser:conformance`).
export default defineConfig({
  test: {
    include: ["test/v3-conformance.browser.test.ts"],
    testTimeout: 60_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }],
    },
  },
});
