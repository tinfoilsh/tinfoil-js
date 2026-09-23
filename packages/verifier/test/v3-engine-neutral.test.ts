// Guards the v3 verifier's browser compatibility: no node:-namespace imports
// and no Node-only Buffer usage anywhere under src/v3 — the same code must
// run on WebCrypto in Node and browsers.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const v3Root = join(__dirname, "..", "src", "v3");

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(p));
    else if (entry.name.endsWith(".ts")) out.push(p);
  }
  return out;
}

describe("v3 verifier is engine-neutral", () => {
  for (const file of tsFiles(v3Root)) {
    it(`${file.slice(v3Root.length + 1)} has no node:-namespace imports or Buffer usage`, () => {
      const src = readFileSync(file, "utf-8");
      expect(src).not.toMatch(/["']node:/);
      expect(src).not.toMatch(/\bBuffer\b/);
      expect(src).not.toMatch(/\brequire\s*\(/);
    });
  }
});
