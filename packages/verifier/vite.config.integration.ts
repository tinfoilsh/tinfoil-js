/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  test: {
    include: ["**/*.browser.integration.test.ts"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: "playwright",
      headless: true,
      instances: [
        {
          browser: "chromium",
          launch: {
            args: [
              '--disable-web-security',
              '--disable-features=IsolateOrigins,site-per-process',
            ],
          },
        },
      ],
    },
  },
});
