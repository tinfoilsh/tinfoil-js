/** The HTTP entry shares the root's clients and errors without exporting API adapters. */
import { describe, expect, expectTypeOf, it } from "vitest";
import * as http from "../src/http.js";
import * as root from "../src/index.js";

const HTTP_EXPORTS = [
  "EnclaveHTTPClient",
  "RouterHTTPClient",
  "GatewayHTTPClient",
  "fetchCatalog",
  "TinfoilError",
  "ConfigurationError",
  "NetworkError",
  "AttestationError",
  "sessionRecoveryToken",
  "serializeSessionRecoveryToken",
  "deserializeSessionRecoveryToken",
  "decryptResponseWithToken",
  "SDK_VERSION",
] as const;

describe("the HTTP entry", () => {
  it("exports the same HTTP classes and helpers as the package root", () => {
    expect(Object.keys(http).sort()).toEqual([...HTTP_EXPORTS].sort());
    for (const name of HTTP_EXPORTS) expect(http[name]).toBe(root[name]);
  });

  it("exposes the HTTP options and verification facts without requiring the root entry", () => {
    expectTypeOf<[
      http.Fetch, http.TransportMode, http.VerificationCheck, http.CallOptions,
      http.EnclaveOptions, http.RouterOptions, http.GatewayOptions, http.ModelPin,
      http.Catalog, http.CatalogEntry, http.ReplicaVerification, http.ErrorCategory,
      http.SessionRecoveryToken,
    ]>().toEqualTypeOf<[
      root.Fetch, root.TransportMode, root.VerificationCheck, root.CallOptions,
      root.EnclaveOptions, root.RouterOptions, root.GatewayOptions, root.ModelPin,
      root.Catalog, root.CatalogEntry, root.ReplicaVerification, root.ErrorCategory,
      root.SessionRecoveryToken,
    ]>();
  });
});
