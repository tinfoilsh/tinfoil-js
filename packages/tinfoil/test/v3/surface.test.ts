/**
 * The public surface of the client: exactly the names the surface
 * specification lists, with the shapes callers rely on. A name added or
 * removed by accident fails here. Placeholders still reject with a clear
 * "not implemented" error, which pins the shape before the behaviour lands.
 */
import { readFileSync } from "node:fs";
import OpenAI from "openai";
import { describe, expect, it } from "vitest";
import * as browser from "../../src/v3/index.browser.js";
import * as surface from "../../src/v3/index.js";
import { NotImplementedError } from "../../src/v3/internal/not-implemented.js";

/** Every runtime export, sorted. Type-only exports are checked by compiling this file. */
const EXPORTS = [
  // clients
  "createClient",
  "TinfoilClient",
  "EnclaveHTTPClient",
  "EnclaveOpenAIClient",
  "RouterHTTPClient",
  "RouterOpenAIClient",
  "GatewayHTTPClient",
  "GatewayOpenAIClient",
  "fetchCatalog",
  // errors
  "TinfoilError",
  "ConfigurationError",
  "NetworkError",
  "AttestationError",
  // version
  "SDK_VERSION",
  // OpenAI helpers and errors
  "toFile",
  "APIPromise",
  "PagePromise",
  "OpenAIError",
  "APIError",
  "APIConnectionError",
  "APIConnectionTimeoutError",
  "APIUserAbortError",
  "NotFoundError",
  "ConflictError",
  "RateLimitError",
  "BadRequestError",
  "AuthenticationError",
  "InternalServerError",
  "PermissionDeniedError",
  "UnprocessableEntityError",
].sort();

const ATTESTED_CLIENT_METHODS = ["baseURL", "enclave", "repo", "current", "ensureVerified", "reverify"].sort();
const GATEWAY_CLIENT_METHODS = ["baseURL", "models", "ensureVerified", "current"].sort();
const OPENAI_CLIENT_METHODS = ["httpClient"];

/** The type-only exports, pinned under the test typecheck: a removed or renamed type fails compilation here. */
type TypeExports = [
  surface.TransportMode,
  surface.VerificationCheck,
  surface.EnclaveOptions,
  surface.RouterOptions,
  surface.GatewayOptions,
  surface.ModelPin,
  surface.Catalog,
  surface.CatalogEntry,
  surface.ReplicaVerification,
  surface.OpenAIOptions,
  surface.ErrorCategory,
  surface.Uploadable,
];
const typeExports: TypeExports | undefined = undefined;
void typeExports;

const methodsOf = (cls: { prototype: object }): string[] =>
  Object.getOwnPropertyNames(cls.prototype)
    .filter((n) => n !== "constructor")
    .sort();

const staticsOf = (cls: object): string[] => Object.getOwnPropertyNames(cls).filter((n) => !["length", "name", "prototype"].includes(n));

describe("public surface", () => {
  it("exports exactly the specified names from both entries", () => {
    expect(Object.keys(surface).sort()).toEqual(EXPORTS);
    expect(Object.keys(browser).sort()).toEqual(EXPORTS);
  });

  it("shapes the HTTP clients as specified: a `create` factory and the verification methods", () => {
    for (const cls of [surface.EnclaveHTTPClient, surface.RouterHTTPClient]) {
      expect(staticsOf(cls)).toEqual(["create"]);
      expect(methodsOf(cls)).toEqual(ATTESTED_CLIENT_METHODS);
    }
    expect(staticsOf(surface.GatewayHTTPClient)).toEqual(["create"]);
    expect(methodsOf(surface.GatewayHTTPClient)).toEqual(GATEWAY_CLIENT_METHODS);
  });

  it("shapes the OpenAI clients as OpenAI subclasses with a `create` factory and `httpClient`", () => {
    for (const cls of [surface.TinfoilClient, surface.EnclaveOpenAIClient, surface.RouterOpenAIClient, surface.GatewayOpenAIClient]) {
      expect(Object.getPrototypeOf(cls)).toBe(OpenAI);
      expect(staticsOf(cls)).toEqual(["create"]);
      expect(methodsOf(cls)).toEqual(OPENAI_CLIENT_METHODS);
    }
    expect(typeof surface.createClient).toBe("function");
    expect(typeof surface.fetchCatalog).toBe("function");
  });

  it("reports the package version", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string };
    expect(surface.SDK_VERSION).toBe(pkg.version);
  });

  it("classifies errors under one supertype with the category in the message", () => {
    const configuration = new surface.ConfigurationError("bad option");
    const network = new surface.NetworkError("unreachable", { cause: new Error("ECONNRESET") });
    const attestation = new surface.AttestationError("rejected");
    for (const err of [configuration, network, attestation]) expect(err).toBeInstanceOf(surface.TinfoilError);
    expect(configuration.message).toBe("configuration error: bad option");
    expect(network.message).toBe("network error: unreachable");
    expect(attestation.message).toBe("attestation error: rejected");
    expect([configuration.category, network.category, attestation.category]).toEqual(["configuration", "network", "attestation"]);
    expect([configuration.name, network.name, attestation.name]).toEqual(["ConfigurationError", "NetworkError", "AttestationError"]);
    expect((network.cause as Error).message).toBe("ECONNRESET");
  });

  it("rejects every placeholder with a not-implemented error", async () => {
    const pending: Promise<unknown>[] = [
      surface.createClient(),
      surface.TinfoilClient.create(),
      surface.EnclaveHTTPClient.create("enclave.example", "tinfoilsh/repo"),
      surface.EnclaveOpenAIClient.create("enclave.example", "tinfoilsh/repo"),
      surface.RouterHTTPClient.create(),
      surface.RouterOpenAIClient.create(),
      surface.GatewayHTTPClient.create(),
      surface.GatewayOpenAIClient.create(),
      surface.fetchCatalog("gateway.example"),
    ];
    for (const p of pending) await expect(p).rejects.toBeInstanceOf(NotImplementedError);
  });
});
