/**
 * The v3 client entry loads under Bun and exposes its surface.
 * Run with: bun test test/surface.bun.ts
 */
import { describe, expect, it } from "bun:test";
import * as aiSdk from "../src/ai-sdk.js";
import * as surface from "../src/index.js";
// Resolved through the package's exports map, so these need `npm run build`.
import * as builtRoot from "tinfoil";
import * as builtOpenAI from "tinfoil/openai";

describe("v3 client surface under Bun", () => {
  it("exposes the clients, the errors and the version", () => {
    for (const name of ["EnclaveHTTPClient", "RouterHTTPClient", "GatewayHTTPClient", "TinfoilError", "SDK_VERSION"]) {
      expect(name in surface).toBe(true);
    }
    for (const name of ["createClient", "OpenAIClient", "createRealtimeWebSocket", "APIConnectionError"]) expect(name in builtOpenAI).toBe(true);
    expect(() => new builtOpenAI.OpenAIClient({} as never)).toThrow(builtRoot.ConfigurationError);
    expect(new surface.ConfigurationError("x")).toBeInstanceOf(surface.TinfoilError);
  });

  it("keeps the AI SDK provider on its own entry", async () => {
    expect(Object.keys(aiSdk)).toEqual(["createTinfoil"]);
    expect("createTinfoil" in surface).toBe(false);
    await expect(aiSdk.createTinfoil({})).rejects.toBeInstanceOf(surface.ConfigurationError);
  });

  it("resolves tinfoil to the HTTP clients without the OpenAI clients", () => {
    for (const name of ["EnclaveHTTPClient", "RouterHTTPClient", "GatewayHTTPClient", "TinfoilError", "ConfigurationError", "NetworkError", "AttestationError"]) {
      expect(name in builtRoot).toBe(true);
    }
    for (const name of ["createClient", "OpenAIClient", "createTinfoil"]) expect(name in builtRoot).toBe(false);
  });

  it("checks client options before any network I/O", async () => {
    await expect(surface.EnclaveHTTPClient.create("", { kind: "repoPin", repo: "tinfoilsh/repo" })).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(surface.GatewayHTTPClient.create({ url: "http://gateway.example/v1/" })).rejects.toBeInstanceOf(surface.ConfigurationError);
  });
});
