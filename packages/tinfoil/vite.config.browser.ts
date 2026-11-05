/// <reference types="vitest" />
import { defineConfig, type Plugin } from "vite";
import { existsSync, readFileSync } from "fs";
import { dirname, resolve } from "path";
import { playwright } from "@vitest/browser-playwright";

/**
 * Resolves the modules the package's browser field maps to their browser
 * variants, as a bundler does from the published package, so the browser
 * tests run the browser build's modules from source. The mapping is read
 * from package.json, so the harness can't drift from the field, and every
 * mapped module must exist as source on both sides.
 */
function browserField(): Plugin {
  const pkg = JSON.parse(readFileSync(resolve(__dirname, "package.json"), "utf8")) as { browser: Record<string, string> };
  const toSource = (dist: string): string => resolve(__dirname, dist.replace(/^\.\/dist\//, "src/").replace(/\.js$/, ".ts"));
  const mapped = new Map<string, string>();
  for (const [from, to] of Object.entries(pkg.browser)) {
    // The entry point is built output a consumer's bundler picks through
    // the exports map, not a module another source file imports; the tests
    // import both entries by name and compare their surfaces.
    if (from === "./dist/index.js") continue;
    const [source, variant] = [toSource(from), toSource(to)];
    if (!existsSync(source) || !existsSync(variant)) throw new Error(`package.json maps ${from} to ${to}, but a source module is missing`);
    mapped.set(source, variant);
  }
  if (mapped.size === 0) throw new Error("package.json maps no module for the browser");
  return {
    name: "tinfoil-browser-field",
    enforce: "pre",
    resolveId(source, importer) {
      if (importer === undefined || !source.startsWith(".")) return null;
      const target = resolve(dirname(importer.split("?")[0]!), source).replace(/\.js$/, ".ts");
      return mapped.get(target) ?? null;
    },
  };
}

export default defineConfig({
  plugins: [browserField()],
  optimizeDeps: {
    include: ["openai", "ai", "@ai-sdk/openai-compatible"],
  },
  test: {
    include: ["test/*.browser.test.ts"],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }, { browser: "webkit" }],
    },
  },
});
