import { build } from "esbuild";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import ts from "typescript";

const root = fileURLToPath(new URL("../", import.meta.url));
await rm(new URL("../dist/", import.meta.url), {
  recursive: true,
  force: true,
});
await mkdir(new URL("../dist/", import.meta.url), { recursive: true });
const declarations = spawnSync(
  process.execPath,
  ["../../node_modules/typescript/bin/tsc", "--emitDeclarationOnly"],
  {
    cwd: root,
    stdio: "inherit",
  },
);
if (declarations.status !== 0) process.exit(declarations.status ?? 1);
// Keep only declarations reachable from the package's sole public entry.
const reachable = new Set();
async function visit(file) {
  if (reachable.has(file)) return;
  reachable.add(file);
  const source = await readFile(file, "utf8");
  for (const { fileName } of ts.preProcessFile(source).importedFiles) {
    if (!fileName.startsWith(".")) continue;
    await visit(resolve(dirname(file), fileName.replace(/\.js$/, ".d.ts")));
  }
}
await visit(resolve(root, "dist/index.d.ts"));
async function prune(directory) {
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, item.name);
    if (item.isDirectory()) {
      await prune(path);
      if (!(await readdir(path)).length) await rm(path, { recursive: true });
    } else if (!reachable.has(path)) await rm(path);
  }
}
await prune(resolve(root, "dist"));
// Only the public entry is bundled. Unreferenced fixture factories and block
// adapters are removed. Source maps are omitted to avoid including private hooks.
await build({
  absWorkingDir: root,
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.js",
  bundle: true,
  packages: "external",
  platform: "neutral",
  format: "esm",
  target: "es2020",
  treeShaking: true,
  sourcemap: false,
});
