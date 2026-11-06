/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  test: {
    include: ["test/*.test.ts"],
    // The browser lanes run their own configs; both their patterns match the include.
    exclude: ["test/*.browser.test.ts", "test/*.browser.integration.test.ts"],
    testTimeout: 30_000,
  },
  resolve: {
    alias: {
      // The tests exercise the verifier from its sources, so test helpers
      // that reach into the verifier share one module instance with the client.
      "@tinfoilsh/verifier": resolve(__dirname, "../verifier/src/index.ts"),
    },
  },
});
