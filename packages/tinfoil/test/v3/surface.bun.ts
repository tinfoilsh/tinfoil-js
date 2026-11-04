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

  it("rejects a placeholder factory with a not-implemented error", async () => {
    await expect(surface.EnclaveHTTPClient.create("enclave.example", "tinfoilsh/repo")).rejects.toThrow(/not implemented/);
  });
});
