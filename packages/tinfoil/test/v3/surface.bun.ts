/**
 * The v3 client entry loads under Bun and exposes its surface.
 * Run with: bun test test/v3/surface.bun.ts
 */
import { describe, expect, it } from "bun:test";
import * as surface from "../../src/v3/index.js";

describe("v3 client surface under Bun", () => {
  it("exposes the clients, the errors and the version", () => {
    for (const name of ["createClient", "EnclaveHTTPClient", "RouterHTTPClient", "GatewayHTTPClient", "TinfoilError", "SDK_VERSION"]) {
      expect(name in surface).toBe(true);
    }
    expect(new surface.ConfigurationError("x")).toBeInstanceOf(surface.TinfoilError);
  });

  it("checks client options before any network I/O", async () => {
    await expect(surface.EnclaveHTTPClient.create("", "tinfoilsh/repo")).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(surface.GatewayHTTPClient.create({ url: "http://gateway.example/v1/" })).rejects.toBeInstanceOf(surface.ConfigurationError);
  });
});
