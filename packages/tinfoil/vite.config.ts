/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  test: {
    include: ["test/*.test.ts", "test/v3/*.test.ts"],
    exclude: ["test/*.browser.integration.test.ts", "test/v3/*.browser.test.ts"],
    testTimeout: 30_000,
  },
  resolve: {
    alias: {
      // The v3 tests exercise the verifier from its sources, so test helpers
      // that reach into the verifier share one module instance with the client.
      "@tinfoilsh/verifier/v3": resolve(__dirname, "../verifier/src/v3/index.ts"),
    },
  },
});
