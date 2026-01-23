import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgPath = resolve(__dirname, "../package.json");

describe("package.json browser field", () => {
  it("all browser field mappings have corresponding source files", () => {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const browserField = pkg.browser as Record<string, string> | undefined;

    if (!browserField) {
      return; // No browser field, nothing to validate
    }

    for (const [distPath, browserDistPath] of Object.entries(browserField)) {
      // Convert dist path to source path
      // "./dist/foo.js" -> "./src/foo.ts"
      const sourcePath = browserDistPath
        .replace("./dist/", "./src/")
        .replace(".js", ".ts");

      const fullPath = resolve(__dirname, "..", sourcePath);

      expect(
        existsSync(fullPath),
        `Browser field maps "${distPath}" -> "${browserDistPath}", ` +
          `but source file "${sourcePath}" does not exist. ` +
          `Create ${sourcePath} to provide a browser-compatible stub.`
      ).toBe(true);
    }
  });

  it("browser field mappings follow consistent naming convention", () => {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const browserField = pkg.browser as Record<string, string> | undefined;

    if (!browserField) {
      return;
    }

    for (const [distPath, browserDistPath] of Object.entries(browserField)) {
      // Verify the mapping follows the expected pattern:
      // "./dist/foo.js" -> "./dist/foo.browser.js"
      const expectedBrowserPath = distPath.replace(".js", ".browser.js");

      expect(
        browserDistPath,
        `Browser field mapping "${distPath}" -> "${browserDistPath}" ` +
          `doesn't follow naming convention. Expected "${expectedBrowserPath}"`
      ).toBe(expectedBrowserPath);
    }
  });
});
