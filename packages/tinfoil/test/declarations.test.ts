/**
 * The published type declarations, as `npm run build` emits them: only the
 * files the entries reach, nothing marked internal, no seam or in-package
 * helper, no internal type named in a public signature, and the clients
 * with private constructors. Skipped until the package has been built.
 */
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { declarationsUnder, reachableDeclarations } from "../../../scripts/prune-declarations.mjs";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const entries = ["index.d.ts", "index.browser.d.ts", "ai-sdk.d.ts", "unsafe.d.ts"].map((e) => `${dist}${e}`);
const built = entries.every((e) => existsSync(e));

/** Names of internal types, seams and in-package helpers that must not appear in any published declaration. */
const FORBIDDEN = [
  /@internal/,
  /KeyedTransport/,
  /GatewayTransport/,
  /\bSeams\b/,
  /Seams\b/,
  /\bTOKEN\b/,
  /create(Enclave|Router|Gateway)HTTPClient/,
  /createUnverifiedClient/,
  /createTinfoilClient/,
  /create(Enclave|Router|Gateway)OpenAIClient/,
  /createTinfoilProvider/,
  /openAIURLOf|setOpenAIURL|attestedFetch|checkEnclaveOptions|checkUnverifiedOptions|modeFor|resolveTransportMode/,
];

/** The classes a consumer must not be able to construct, and the declaration file of each. */
const PRIVATELY_CONSTRUCTED: Record<string, string> = {
  EnclaveHTTPClient: "enclave-client.d.ts",
  RouterHTTPClient: "router-client.d.ts",
  GatewayHTTPClient: "gateway-client.d.ts",
  TinfoilClient: "openai-client.d.ts",
  EnclaveOpenAIClient: "openai-client.d.ts",
  RouterOpenAIClient: "openai-client.d.ts",
  GatewayOpenAIClient: "openai-client.d.ts",
  UnverifiedClient: "internal/unsafe-client.d.ts",
};

const read = (file: string): string => readFileSync(file, "utf8");

describe.skipIf(!built)("the published declarations", () => {
  it("are exactly the files the entries reach", () => {
    const reachable = [...reachableDeclarations(entries)].sort();
    expect(declarationsUnder(dist).sort()).toEqual(reachable);
  });

  it("name no internal type, seam or in-package helper", () => {
    for (const file of declarationsUnder(dist)) {
      const source = read(file);
      for (const pattern of FORBIDDEN) expect(source, `${file} matches ${pattern}`).not.toMatch(pattern);
    }
  });

  it("declare the clients with a private constructor", () => {
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
