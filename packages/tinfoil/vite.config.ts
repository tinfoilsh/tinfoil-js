/// <reference types="vitest" />
import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  test: {
    include: ["test/*.test.ts"],
    exclude: ["test/*.browser.test.ts"],
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
