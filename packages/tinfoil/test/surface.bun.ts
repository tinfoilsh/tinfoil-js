/**
 * The v3 client entry loads under Bun and exposes its surface.
 * Run with: bun test test/surface.bun.ts
 */
import { describe, expect, it } from "bun:test";
import * as aiSdk from "../src/ai-sdk.js";
import * as surface from "../src/index.js";
// Resolved through the package's exports map, so these need `npm run build`.
import * as builtHTTP from "tinfoil/http";
import * as builtRoot from "tinfoil";

describe("v3 client surface under Bun", () => {
  it("exposes the clients, the errors and the version", () => {
    for (const name of ["createClient", "EnclaveHTTPClient", "RouterHTTPClient", "GatewayHTTPClient", "TinfoilError", "SDK_VERSION"]) {
      expect(name in surface).toBe(true);
    }
    expect(new surface.ConfigurationError("x")).toBeInstanceOf(surface.TinfoilError);
  });

  it("keeps the AI SDK provider on its own entry", async () => {
    expect(Object.keys(aiSdk)).toEqual(["createTinfoil"]);
    expect("createTinfoil" in surface).toBe(false);
    await expect(aiSdk.createTinfoil({})).rejects.toBeInstanceOf(surface.ConfigurationError);
  });

  it("resolves tinfoil/http to the root's HTTP clients without the OpenAI clients", () => {
    for (const name of ["EnclaveHTTPClient", "RouterHTTPClient", "GatewayHTTPClient", "TinfoilError", "ConfigurationError", "NetworkError", "AttestationError"]) {
      expect(name in builtHTTP).toBe(true);
    }
    // Every export is the root's own object, so instanceof works across both entries.
    for (const [name, value] of Object.entries(builtHTTP as Record<string, unknown>)) {
      expect(value).toBe((builtRoot as Record<string, unknown>)[name]);
    }
    for (const name of ["createClient", "TinfoilClient", "EnclaveOpenAIClient", "RouterOpenAIClient", "GatewayOpenAIClient", "createTinfoil"]) {
      expect(name in builtHTTP).toBe(false);
    }
  });

  it("checks client options before any network I/O", async () => {
    await expect(surface.EnclaveHTTPClient.create("", "tinfoilsh/repo")).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(surface.GatewayHTTPClient.create({ url: "http://gateway.example/v1/" })).rejects.toBeInstanceOf(surface.ConfigurationError);
  });
});
