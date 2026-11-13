/** Exercise the published exports and browser mappings, not aliases to the source tree. */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { describe, expect, it } from "vitest";

const packageRoot = fileURLToPath(new URL("../", import.meta.url));

/** Bundle a consumer of the published entries, retaining the factories without making a network request. */
async function bundleConsumer(source: string) {
  const fixture = mkdtempSync(join(packageRoot, ".http-bundle-"));
  const modules: string[] = [];
  const entryModules: string[] = [];
  const dynamicImports: string[] = [];
  try {
    const entry = join(fixture, "entry.js");
    writeFileSync(entry, source);
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

/**
 * Import the published `entry` in a fresh Node process whose resolver throws on
 * any specifier that matches `banned` (a regular expression source), then
 * check that `factory` is a function on the loaded module.
 */
function assertLoadsWithout(entry: string, banned: string, factory: string) {
  execFileSync(process.execPath, ["--input-type=module", "--eval", `
    import { registerHooks } from "node:module";
    const banned = new RegExp(${JSON.stringify(banned)});
    registerHooks({
      resolve(specifier, context, nextResolve) {
        if (banned.test(specifier)) throw new Error(${JSON.stringify(entry)} + " loaded " + specifier);
        return nextResolve(specifier, context);
      },
    });
    const loaded = await import(${JSON.stringify(entry)});
    if (typeof loaded${factory} !== "function") throw new Error("Missing " + ${JSON.stringify(factory)});
  `], { cwd: packageRoot, stdio: "pipe" });
}

describe("the published HTTP entry", () => {
  it("loads in Node without resolving an API adapter", () => {
    assertLoadsWithout("tinfoil/http", "^(?:openai|ai)(?:/|$)|^@ai-sdk/", ".RouterHTTPClient.create");
  });
  it.each([false, true])("keeps API adapters out of a consumer (lazy: %s)", async (lazy) => {
    const { modules, entryModules, dynamicImports } = await bundleConsumer(lazy
      ? 'export const loadHTTP = () => import("tinfoil/http");\n'
      : 'export { RouterHTTPClient, EnclaveHTTPClient, GatewayHTTPClient } from "tinfoil/http";\n');
    expect(modules.some((id) => id.endsWith("/tinfoil/dist/router-client.js"))).toBe(true);
    expect(modules.some((id) => id.endsWith("/internal/platform.browser.js"))).toBe(true);
    expect(modules.some((id) => id.endsWith("/internal/transport/ehbp.js"))).toBe(true);
    expect(modules.filter((id) => /\/node_modules\/(?:openai|ai|@ai-sdk)\//.test(id))).toEqual([]);
    expect(modules.filter((id) => /\/(?:openai-client|ai-sdk|realtime)\.js$/.test(id))).toEqual([]);
    expect(modules.filter((id) => /\/internal\/(?:platform|transport\/tls)\.js$/.test(id))).toEqual([]);
    if (lazy) {
      expect(dynamicImports).toHaveLength(1);
      expect(entryModules.filter((id) => /\/(?:packages\/tinfoil\/dist|node_modules)\//.test(id))).toEqual([]);
    }
  });
});

// The AI SDK and its OpenAI-compatible provider are optional peers that only
// `tinfoil/ai-sdk` needs, so the root entry must load and bundle without them.
describe("the published root entry", () => {
  it("loads in Node without resolving the AI SDK", () => {
    assertLoadsWithout("tinfoil", "^ai(?:/|$)|^@ai-sdk/", ".createClient");
  });
  it("keeps the AI SDK out of a consumer", async () => {
    const { modules } = await bundleConsumer('export { createClient, RouterOpenAIClient } from "tinfoil";\n');
    expect(modules.some((id) => id.endsWith("/tinfoil/dist/openai-client.js"))).toBe(true);
    expect(modules.filter((id) => /\/node_modules\/(?:ai|@ai-sdk)\//.test(id))).toEqual([]);
    expect(modules.filter((id) => /\/ai-sdk\.js$/.test(id))).toEqual([]);
  });
});
