/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";
import { playwright } from "@vitest/browser-playwright";
import { browserRelay } from "./test/browser-relay.js";

export default defineConfig({
  plugins: [browserRelay()],
  test: {
    include: ["test/*.browser.test.ts"],
    exclude: ["test/*.browser.integration.test.ts"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [
        { browser: "chromium" },
        {
          browser: "webkit",
          provider: playwright({
            launchOptions: process.env.TINFOIL_TEST_WEBKIT_EXECUTABLE
              ? { executablePath: process.env.TINFOIL_TEST_WEBKIT_EXECUTABLE }
              : undefined,
          }),
        },
      ],
    },
  },
  resolve: {
    alias: {
      'tinfoil': resolve(__dirname, 'src/index.browser.ts'),
    },
  },
});
