/**
 * The checks both packages run on their published type declarations, as
 * `npm run build` emits them; each package's `test/declarations.test.ts`
 * supplies its entries, the names that must not appear, and the classes
 * that must have a private constructor. Skipped until the package has been
 * built. Also the test of the prune itself, on a tree built for the purpose.
 */
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { declarationsUnder, pruneDeclarations, reachableDeclarations } from "../scripts/declarations.mjs";

export interface PublishedDeclarations {
  /** The package's `dist` directory, as an absolute path ending with `/`. */
  readonly dist: string;
  /** The declaration files of the package's entry points. */
  readonly entries: readonly string[];
  /** Names of internal types, seams and test-only entry points that must not appear in any published declaration. */
  readonly forbidden: readonly RegExp[];
  /** The classes a consumer must not be able to construct, and the declaration file of each. */
  readonly privatelyConstructed: Readonly<Record<string, string>>;
}

const read = (file: string): string => readFileSync(file, "utf8");

/** The members of `export declare class <name>` in `source`, or undefined when it declares no such class. */
function classBody(source: string, name: string): string | undefined {
  // A class body ends at the first closing brace on its own line; a brace inside a doc comment doesn't end it.
  const body = /export declare class (\w+)[^\n]*\n([\s\S]*?)\n\}/g;
  for (const [, cls, members] of source.matchAll(body)) if (cls === name) return members;
  return undefined;
}

export function describePublishedDeclarations({ dist, entries, forbidden, privatelyConstructed }: PublishedDeclarations): void {
  const built = entries.every((e) => existsSync(e));

  describe.skipIf(!built)("the published declarations", () => {
    it("are exactly the files the entries reach, so a prune finds nothing more to remove", () => {
      const reachable = [...reachableDeclarations(entries)].sort();
      expect(declarationsUnder(dist).sort()).toEqual(reachable);
      const dryRun = pruneDeclarations(dist, entries, { dryRun: true });
      expect(dryRun.kept.sort()).toEqual(reachable);
      expect(dryRun.removed).toEqual([]);
      expect(dryRun.leaking).toEqual([]);
    });

    it("name no internal type, seam or test-only entry point", () => {
      for (const file of declarationsUnder(dist)) {
        const source = read(file);
        for (const pattern of forbidden) expect(source, `${file} matches ${pattern}`).not.toMatch(pattern);
      }
    });

    it("declare the factory-built classes with a private constructor", () => {
      for (const [name, file] of Object.entries(privatelyConstructed)) {
        const members = classBody(read(`${dist}${file}`), name);
        expect(members, `${name} in ${file}`).toBeDefined();
        expect(members).toMatch(/private constructor\(\);/);
        expect(members).not.toMatch(/\n\s+constructor\(/);
      }
    });
  });
}

/** The prune on a tree built for the purpose: it removes what the entry doesn't reach, keeps what it does, and never follows a link out of the tree. */
export function describeDeclarationPrune(): void {
  describe("the declaration prune", () => {
    it("removes the unreachable declarations and their maps, keeps the reachable ones, and skips links", () => {
      const tmp = mkdtempSync(join(tmpdir(), "declarations-"));
      try {
        const dist = join(tmp, "dist");
        const outside = join(tmp, "outside.d.ts");
        mkdirSync(join(dist, "internal"), { recursive: true });
        writeFileSync(join(dist, "index.d.ts"), 'export { A } from "./a.js";\nexport type { B } from "./internal/b.js";\n/** @internal */\nexport {};\n');
        writeFileSync(join(dist, "a.d.ts"), 'import type { B } from "./internal/b.js";\nexport declare class A { b: B; }\n');
        writeFileSync(join(dist, "internal", "b.d.ts"), "export type B = string;\n");
        writeFileSync(join(dist, "internal", "c.d.ts"), 'import type { B } from "./b.js";\nexport declare const c: B;\n');
        writeFileSync(join(dist, "internal", "c.d.ts.map"), "{}");
        writeFileSync(join(dist, "a.js"), "export class A {}\n");
        writeFileSync(outside, "export {};\n");
        symlinkSync(outside, join(dist, "linked.d.ts"));
        const entry = join(dist, "index.d.ts");

        const dryRun = pruneDeclarations(dist, [entry], { dryRun: true });
        expect(dryRun.removed).toEqual([join(dist, "internal", "c.d.ts")]);
        expect(existsSync(join(dist, "internal", "c.d.ts"))).toBe(true);

        const pruned = pruneDeclarations(dist, [entry]);
        expect(pruned.kept.sort()).toEqual([join(dist, "a.d.ts"), join(dist, "index.d.ts"), join(dist, "internal", "b.d.ts")]);
        expect(pruned.removed).toEqual([join(dist, "internal", "c.d.ts")]);
        expect(pruned.leaking).toEqual([entry]);
        expect(existsSync(join(dist, "internal", "c.d.ts"))).toBe(false);
        expect(existsSync(join(dist, "internal", "c.d.ts.map"))).toBe(false);
        expect(existsSync(join(dist, "a.js"))).toBe(true);
        expect(lstatSync(join(dist, "linked.d.ts")).isSymbolicLink()).toBe(true);
        expect(existsSync(outside)).toBe(true);
        expect(declarationsUnder(dist).sort()).toEqual(pruned.kept.sort());
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    });

    it("refuses an entry that doesn't exist or an import it cannot resolve", () => {
      const tmp = mkdtempSync(join(tmpdir(), "declarations-"));
      try {
        expect(() => reachableDeclarations([join(tmp, "missing.d.ts")])).toThrow(/does not exist/);
        writeFileSync(join(tmp, "index.d.ts"), 'export { x } from "./nowhere.js";\n');
        expect(() => reachableDeclarations([join(tmp, "index.d.ts")])).toThrow(/cannot resolve "\.\/nowhere\.js"/);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    });
  });
}
