/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  test: {
    include: ["test/*.test.ts"],
    exclude: ["test/*.browser.integration.test.ts"],
    testTimeout: 30_000,
  },
});
