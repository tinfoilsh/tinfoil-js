/**
 * The published type declarations, as `npm run build` emits them: only the
 * files the entry reaches, nothing marked internal, no test-only entry
 * point, no internal type named in a public signature, and the classes the
 * factories build with private constructors. Skipped until the package has
 * been built.
 */
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { declarationsUnder, reachableDeclarations } from "../../../scripts/prune-declarations.mjs";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const entry = `${dist}index.d.ts`;
const built = existsSync(entry);

/** Names of internal types, seams and test-only entry points that must not appear in any published declaration. */
const FORBIDDEN = [/@internal/, /dangerousTestOnly/i, /\bParts\b/, /ProvenanceClient/, /ConfigVerifier/, /FreshnessVerifier/, /InjectedRoots/, /buildVerifier/, /verificationOf/, /VerificationFields/, /DecodedDocument/];

/** The classes a consumer must not be able to construct, and the declaration file of each. */
const PRIVATELY_CONSTRUCTED: Record<string, string> = { Verification: "verification.d.ts", Verifier: "verifier.d.ts" };

const read = (file: string): string => readFileSync(file, "utf8");

describe.skipIf(!built)("the published declarations", () => {
  it("are exactly the files the entry reaches", () => {
    const reachable = [...reachableDeclarations([entry])].sort();
    expect(declarationsUnder(dist).sort()).toEqual(reachable);
  });

  it("name no internal type, seam or test-only entry point", () => {
    for (const file of declarationsUnder(dist)) {
      const source = read(file);
      for (const pattern of FORBIDDEN) expect(source, `${file} matches ${pattern}`).not.toMatch(pattern);
    }
  });

  it("declare the factory-built classes with a private constructor", () => {
    for (const [name, file] of Object.entries(PRIVATELY_CONSTRUCTED)) {
      // A class body ends at the first closing brace on its own line; a brace inside a doc comment doesn't end it.
      const body = /export declare class (\w+)[^\n]*\n([\s\S]*?)\n\}/g;
      const classes = [...read(`${dist}${file}`).matchAll(body)].map(([, cls, members]) => [cls, members] as const);
      const members = classes.find(([cls]) => cls === name)?.[1];
      expect(members, `${name} in ${file}`).toBeDefined();
      expect(members).toMatch(/private constructor\(\);/);
      expect(members).not.toMatch(/\n\s+constructor\(/);
    }
  });
});
