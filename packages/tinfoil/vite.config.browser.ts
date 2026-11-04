/// <reference types="vitest" />
import { defineConfig, type Plugin } from "vite";
import { dirname, resolve } from "path";
import { playwright } from "@vitest/browser-playwright";

/**
 * Resolves the v3 modules the package's browser field maps to their browser
 * variants, as a bundler does from the published package, so the browser
 * tests run the browser build's modules from source.
 */
function browserField(): Plugin {
  const mapped = ["src/v3/internal/platform.ts", "src/v3/internal/cachesecret-store.ts", "src/v3/internal/transport/tls.ts"].map((p) => resolve(__dirname, p));
  return {
    name: "tinfoil-browser-field",
    enforce: "pre",
    resolveId(source, importer) {
      if (importer === undefined || !source.startsWith(".")) return null;
      const target = resolve(dirname(importer.split("?")[0]!), source).replace(/\.js$/, ".ts");
      return mapped.includes(target) ? target.replace(/\.ts$/, ".browser.ts") : null;
    },
  };
}

export default defineConfig({
  plugins: [browserField()],
  optimizeDeps: {
    include: ["openai"],
  },
  test: {
    include: ["test/*.browser.test.ts", "test/v3/*.browser.test.ts"],
    exclude: ["test/*.browser.integration.test.ts"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }, { browser: "webkit" }],
    },
  },
  resolve: {
    alias: {
      'tinfoil': resolve(__dirname, 'src/index.browser.ts'),
    },
  },
});
