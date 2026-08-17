#!/usr/bin/env node
// Copies the shared v3 conformance vectors into test/fixtures/v3-vectors so
// the browser conformance test can import.meta.glob them (the vectors live
// outside this repo). Gitignored; re-run any time the suite changes.
// Source override: TINFOIL_CONFORMANCE_VECTORS=/path/to/vectors/v3

import { cpSync, existsSync, lstatSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

const src =
  process.env.TINFOIL_CONFORMANCE_VECTORS ??
  fileURLToPath(new URL("../../../../tinfoil-conformance/vectors/v3", import.meta.url));
const dst = fileURLToPath(new URL("../test/fixtures/v3-vectors", import.meta.url));

if (!existsSync(src)) {
  console.error(`sync-v3-fixtures: vectors not found at ${src} (set TINFOIL_CONFORMANCE_VECTORS)`);
  process.exit(1);
}

rmSync(dst, { recursive: true, force: true });
mkdirSync(dst, { recursive: true });
cpSync(src, dst, { recursive: true, filter: (p) => lstatSync(p).isDirectory() || p.endsWith(".json") });
console.log(`sync-v3-fixtures: synced ${src} -> ${dst}`);
