/**
 * The public surface of the client: exactly the names the surface
 * specification lists, with the shapes callers rely on. A name added or
 * removed by accident fails here, as does an option check that reaches the
 * network or an experimental export that doesn't say so.
 */
import { readFileSync } from "node:fs";
import OpenAI from "openai";
import { describe, expect, it } from "vitest";
import * as aiSdk from "../../src/v3/ai-sdk.js";
import * as browser from "../../src/v3/index.browser.js";
import * as surface from "../../src/v3/index.js";
import * as unsafeEntry from "../../src/v3/unsafe.js";
import { createEnclaveHTTPClient } from "../../src/v3/enclave-client.js";
import { createGatewayHTTPClient } from "../../src/v3/gateway-client.js";
import { createEnclaveOpenAIClient, createGatewayOpenAIClient, createRouterOpenAIClient } from "../../src/v3/openai-client.js";
import { createRouterHTTPClient } from "../../src/v3/router-client.js";
import type { Fetch } from "../../src/v3/options.js";

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
  // websockets
  "createWebSocket",
  "pinnedWebSocketOptions",
  "createRealtimeWebSocket",
  // errors
  "TinfoilError",
  "ConfigurationError",
  "NetworkError",
  "AttestationError",
  // session recovery
  "sessionRecoveryToken",
  "serializeSessionRecoveryToken",
  "deserializeSessionRecoveryToken",
  "decryptResponseWithToken",
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
const OPENAI_CLIENT_METHODS = ["httpClient", "withOptions"];

/** The type-only exports, pinned under the test typecheck: a removed or renamed type fails compilation here. */
type TypeExports = [
  surface.Fetch,
  surface.TransportMode,
  surface.VerificationCheck,
  surface.EnclaveOptions,
  surface.RouterOptions,
  surface.GatewayOptions,
  surface.ModelPin,
  surface.Catalog,
  surface.CatalogEntry,
  surface.ReplicaVerification,
  surface.WebSocketOptions,
  surface.PinnedWebSocket,
  surface.RealtimeOptions,
  surface.OpenAIOptions,
  surface.ErrorCategory,
  surface.SessionRecoveryToken,
  surface.Uploadable,
];
const typeExports: TypeExports | undefined = undefined;
void typeExports;

const methodsOf = (cls: { prototype: object }): string[] =>
  Object.getOwnPropertyNames(cls.prototype)
    .filter((n) => n !== "constructor")
    .sort();

const staticsOf = (cls: object): string[] => Object.getOwnPropertyNames(cls).filter((n) => !["length", "name", "prototype"].includes(n));

/** A fetch seam that counts the requests made through it. */
function countingFetch(): { fetch: Fetch; calls: number } {
  const counter = {
    calls: 0,
    fetch: (async () => {
      counter.calls++;
      return new Response(new Uint8Array([1]));
    }) as Fetch,
  };
  return counter;
}

/** The exports whose API may change without a major version; each must say so in its doc comment. */
const EXPERIMENTAL_EXPORTS: Record<string, string[]> = {
  "src/v3/gateway-client.ts": ["GatewayHTTPClient", "fetchCatalog"],
  "src/v3/openai-client.ts": ["GatewayOpenAIClient"],
  "src/v3/options.ts": ["GatewayOptions", "ModelPin", "CatalogEntry", "Catalog", "ReplicaVerification"],
};

/** The doc comment that ends right before the export of `name` in `source`, or undefined when there is none. */
function docCommentOf(source: string, name: string): string | undefined {
  const declaration = new RegExp(`\\n(?:/\\*\\*[\\s\\S]*?\\*/\\n)?export (?:async )?(?:class|function|interface|type|const) ${name}\\b`);
  const match = declaration.exec(source);
  return match?.[0].includes("/**") ? match[0] : undefined;
}

/** The `tinfoil/v3/ai-sdk` entry: the AI SDK provider alone, so the AI SDK stays out of bundles that don't use it. */
const AI_SDK_EXPORTS = ["createTinfoil"];
type AiSdkTypeExports = [aiSdk.TinfoilProvider, aiSdk.TinfoilProviderOptions, aiSdk.TinfoilProviderEnclave];
const aiSdkTypeExports: AiSdkTypeExports | undefined = undefined;
void aiSdkTypeExports;

describe("the AI SDK entry", () => {
  it("exports exactly the provider factory, and the main entries don't", () => {
    expect(Object.keys(aiSdk).sort()).toEqual(AI_SDK_EXPORTS);
    expect(typeof aiSdk.createTinfoil).toBe("function");
    expect("createTinfoil" in surface).toBe(false);
    expect("createTinfoil" in browser).toBe(false);
  });

  it("is a published subpath of the package", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { exports: Record<string, Record<string, string>> };
    expect(pkg.exports["./v3/ai-sdk"]).toEqual({ types: "./dist/v3/ai-sdk.d.ts", import: "./dist/v3/ai-sdk.js", default: "./dist/v3/ai-sdk.js" });
  });
});

describe("public surface", () => {
  it("documents the experimental exports as such", () => {
    for (const [file, names] of Object.entries(EXPERIMENTAL_EXPORTS)) {
      const source = readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
      for (const name of names) {
        expect(docCommentOf(source, name), `${name} in ${file}`).toMatch(/@experimental/);
      }
    }
    expect(Object.values(EXPERIMENTAL_EXPORTS).flat().filter((n) => n in surface).sort()).toEqual(["GatewayHTTPClient", "GatewayOpenAIClient", "fetchCatalog"]);
  });

  it("exports exactly the specified names from both entries", () => {
    expect(Object.keys(surface).sort()).toEqual(EXPORTS);
    expect(Object.keys(browser).sort()).toEqual(EXPORTS);
  });

  it("keeps the unsafe entry to the unverified client, its warning and its options type", () => {
    expect(Object.keys(unsafeEntry).sort()).toEqual(["UNVERIFIED_WARNING", "UnverifiedClient"]);
    expect(unsafeEntry.UNVERIFIED_WARNING).toMatch(/insecure/i);
    expect(staticsOf(unsafeEntry.UnverifiedClient)).toEqual(["create"]);
    expect(methodsOf(unsafeEntry.UnverifiedClient)).toEqual(["baseURL", "keyOrigin"]);
    const options: unsafeEntry.UnverifiedOptions | undefined = undefined;
    void options;
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

  it("opens WebSockets through functions that take a client, not through client methods", () => {
    for (const fn of [surface.createWebSocket, surface.pinnedWebSocketOptions, surface.createRealtimeWebSocket]) expect(typeof fn).toBe("function");
    expect(methodsOf(surface.EnclaveHTTPClient)).not.toContain("createWebSocket");
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

  it("checks enclave client options before any network I/O", async () => {
    const fetches = countingFetch();
    await expect(createEnclaveHTTPClient("", "tinfoilsh/repo", {}, { documentFetch: fetches.fetch })).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(createEnclaveOpenAIClient("enclave.example", "tinfoilsh/repo", { baseURL: "http://proxy.example/" }, {}, { documentFetch: fetches.fetch })).rejects.toBeInstanceOf(
      surface.ConfigurationError,
    );
    expect(fetches.calls).toBe(0);
  });

  it("checks gateway client options before any network I/O", async () => {
    const fetches = countingFetch();
    const seams = { catalogFetch: fetches.fetch, documentFetch: fetches.fetch };
    await expect(createGatewayHTTPClient({ url: "http://gateway.example/v1/" }, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(createGatewayOpenAIClient({ pinnedModelsOnly: true }, {}, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    expect(fetches.calls).toBe(0);
  });

  it("checks router client options before any network I/O", async () => {
    await expect(surface.RouterHTTPClient.create({ transportMode: "tls", baseURL: "https://proxy.example/" })).rejects.toBeInstanceOf(
      surface.ConfigurationError,
    );
    await expect(surface.RouterOpenAIClient.create({ baseURL: "http://proxy.example/" })).rejects.toBeInstanceOf(surface.ConfigurationError);
  });

  it("fetches nothing before rejecting router client options", async () => {
    const fetches = countingFetch();
    const seams = { routersFetch: fetches.fetch, documentFetch: fetches.fetch };
    await expect(createRouterHTTPClient({ transportMode: "tls", baseURL: "https://proxy.example/" }, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(createRouterOpenAIClient({ baseURL: "http://proxy.example/" }, {}, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    expect(fetches.calls).toBe(0);
  });
});
