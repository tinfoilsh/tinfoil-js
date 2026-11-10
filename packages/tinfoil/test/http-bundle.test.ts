/** Exercise the published exports and browser mappings, not aliases to the source tree. */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { describe, expect, it } from "vitest";

const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const built = existsSync(join(packageRoot, "dist/http.js"));

/** Bundle a consumer through the public subpath, retaining the factory without making a network request. */
async function bundleConsumer(lazy: boolean) {
  const fixture = mkdtempSync(join(packageRoot, ".http-bundle-"));
  const modules: string[] = [];
  const entryModules: string[] = [];
  const dynamicImports: string[] = [];
  try {
    const entry = join(fixture, "entry.js");
    writeFileSync(entry, lazy
      ? 'export const loadHTTP = () => import("tinfoil/http");\n'
      : 'export { RouterHTTPClient, EnclaveHTTPClient, GatewayHTTPClient } from "tinfoil/http";\n');
    await build({
      configFile: false,
      root: packageRoot,
      publicDir: false,
      logLevel: "silent",
      build: {
        write: false,
        minify: false,
        reportCompressedSize: false,
        rolldownOptions: { input: entry, preserveEntrySignatures: "strict" },
      },
      plugins: [{
        name: "inspect-http-consumer",
        generateBundle(_options, output) {
          for (const chunk of Object.values(output)) {
            if (chunk.type !== "chunk") continue;
            const rendered = Object.entries(chunk.modules)
              .filter(([, module]) => module.renderedLength > 0)
              .map(([id]) => id.replaceAll("\\", "/"));
            modules.push(...rendered);
            if (chunk.isEntry) {
              entryModules.push(...rendered);
              dynamicImports.push(...chunk.dynamicImports);
            }
          }
        },
      }],
    });
    return { modules, entryModules, dynamicImports };
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

describe.skipIf(!built)("the published HTTP entry", () => {
  it("loads in Node without resolving an API adapter", () => {
    execFileSync(process.execPath, ["--input-type=module", "--eval", `
      import { registerHooks } from "node:module";
      registerHooks({
        resolve(specifier, context, nextResolve) {
          if (specifier === "openai" || specifier.startsWith("openai/") || specifier === "ai" || specifier.startsWith("@ai-sdk/")) {
            throw new Error("HTTP entry loaded an API adapter: " + specifier);
          }
          return nextResolve(specifier, context);
        },
      });
      const { RouterHTTPClient } = await import("tinfoil/http");
      if (typeof RouterHTTPClient.create !== "function") throw new Error("Missing HTTP factory");
    `], { cwd: packageRoot, stdio: "pipe" });
  });
  it.each([false, true])("keeps API adapters out of a consumer (lazy: %s)", async (lazy) => {
    const { modules, entryModules, dynamicImports } = await bundleConsumer(lazy);
    expect(modules.some((id) => id.endsWith("/tinfoil/dist/router-client.js"))).toBe(true);
    expect(modules.some((id) => id.endsWith("/internal/platform.browser.js"))).toBe(true);
    expect(modules.some((id) => id.endsWith("/internal/transport/ehbp.js"))).toBe(true);
    expect(modules.filter((id) => /\/node_modules\/(?:openai|ai|@ai-sdk)\//.test(id))).toEqual([]);
    expect(modules.filter((id) => /\/(?:openai-client|ai-sdk|realtime)\.js$/.test(id))).toEqual([]);
    expect(modules.filter((id) => /\/internal\/(?:platform|transport\/tls|cachesecret-store)\.js$/.test(id))).toEqual([]);
    if (lazy) {
      expect(dynamicImports).toHaveLength(1);
      expect(entryModules.filter((id) => /\/(?:packages\/tinfoil\/dist|node_modules)\//.test(id))).toEqual([]);
    }
  });
});
