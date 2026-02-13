/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  define: {
    'process.env.TINFOIL_API_KEY': JSON.stringify(process.env.TINFOIL_API_KEY ?? ''),
  },
  test: {
    include: ["test/*.browser.integration.test.ts"],
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
  resolve: {
    alias: {
      'tinfoil': resolve(__dirname, 'src/index.browser.ts'),
    },
  },
});
