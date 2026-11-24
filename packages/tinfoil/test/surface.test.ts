/**
 * The public surface of the client: exactly the names the surface
 * specification lists, with the shapes callers rely on. A name added or
 * removed by accident fails here, as does an option check that reaches the
 * network or an experimental export that doesn't say so.
 */
import { readFileSync } from "node:fs";
import OpenAI from "openai";
import { describe, expect, it } from "vitest";
import * as aiSdk from "../src/ai-sdk.js";
import * as browser from "../src/index.browser.js";
import * as surface from "../src/index.js";
import * as openaiEntry from "../src/openai.js";
import * as unsafeEntry from "../src/unsafe.js";
import { createEnclaveHTTPClient } from "../src/enclave-client.js";
import { createGatewayHTTPClient } from "../src/gateway-client.js";
import { createTinfoilClient } from "../src/openai-client.js";
import { createRouterHTTPClient } from "../src/router-client.js";
import type { Fetch } from "../src/options.js";
import { refusal, FORBIDDEN_TRANSPORT_OPTIONS } from "./helpers/transport-options.js";

/** Every runtime export of the root entry, sorted. Type-only exports are checked by compiling this file. */
const EXPORTS = [
  // clients
  "EnclaveHTTPClient",
  "RouterHTTPClient",
  "GatewayHTTPClient",
  "fetchCatalog",
  // websockets
  "createWebSocket",
  "pinnedWebSocketOptions",
  // fetchers
  "attestationRelay",
  "routerListRelay",
  // errors
  "TinfoilError",
  "ConfigurationError",
  "NetworkError",
  "AttestationError",
  "findTinfoilError",
  // the verifier's error and report schema version, from the copy that this package pins
  "VerificationError",
  "REPORT_SCHEMA_VERSION",
  // session recovery
  "sessionRecoveryToken",
  "serializeSessionRecoveryToken",
  "deserializeSessionRecoveryToken",
  "decryptResponseWithToken",
  // version
  "SDK_VERSION",
].sort();

/** Every runtime export of the `tinfoil/openai` entry, sorted. */
const OPENAI_EXPORTS = [
  "OpenAIClient",
  "createClient",
  "createRealtimeWebSocket",
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

/**
 * Every member of a client type and its kind: an own `property` fixed at
 * construction, a prototype `getter` reflecting the client's state, or a
 * `method`. The key set is pinned under the test typecheck, the kinds at
 * runtime; the own properties of an instance are pinned in each client's
 * tests, where one is built.
 */
type Members<T> = Record<Extract<keyof T, string>, "property" | "getter" | "method">;
const ROUTER_CLIENT_MEMBERS: Members<surface.RouterHTTPClient> = {
  fetch: "property",
  baseURL: "property",
  enclave: "property",
  lastVerification: "method",
  ensureVerified: "method",
  reverify: "method",
  close: "method",
};
const ENCLAVE_CLIENT_MEMBERS: Members<surface.EnclaveHTTPClient> = { ...ROUTER_CLIENT_MEMBERS, trust: "getter" };
const GATEWAY_CLIENT_MEMBERS: Members<surface.GatewayHTTPClient> = { fetch: "property", baseURL: "property", lastVerification: "method", models: "method", ensureVerified: "method", close: "method" };
const UNVERIFIED_CLIENT_MEMBERS: Members<unsafeEntry.UnverifiedClient> = { fetch: "property", baseURL: "property", keyOrigin: "property" };
/** What the OpenAI subclass adds to the OpenAI client. */
const OPENAI_CLIENT_MEMBERS = { httpClient: "property", withOptions: "method" } as const satisfies Pick<Members<openaiEntry.OpenAIClient>, "httpClient" | "withOptions">;

/** The type-only exports, pinned under the test typecheck: a removed or renamed type fails compilation here. */
type TypeExports = [
  surface.Fetch,
  surface.AttestationFetcher,
  surface.RouterListFetcher,
  surface.RelayOptions,
  surface.Transport,
  surface.TLS,
  surface.EHBP,
  surface.VerificationCheck,
  surface.VerificationAttempt,
  surface.OnVerification,
  surface.CallOptions,
  surface.EnclaveOptions,
  surface.RouterOptions,
  surface.GatewayOptions,
  surface.ModelPin,
  surface.Catalog,
  surface.CatalogEntry,
  surface.ReplicaVerification,
  surface.WebSocketOptions,
  surface.PinnedWebSocket,
  surface.ErrorCategory,
  surface.SessionRecoveryToken,
  surface.Policy,
  surface.ArtifactTrust,
  surface.EndorsedArtifacts,
  surface.EmbeddedArtifacts,
  surface.Trust,
  surface.RepoPin,
  surface.ProjectPin,
  surface.SignedBy,
  surface.AuthorizedBy,
  surface.EmbeddedConfig,
  surface.EitherPin,
  surface.VerificationReport,
  surface.VerifiedFacts,
  surface.PartialFacts,
  surface.ExpectedFacts,
  surface.MeasuredFacts,
  surface.CPUEvidence,
  surface.Step,
  surface.StepStatus,
  surface.Layer,
  surface.VerificationMetadata,
  surface.ArtifactVerification,
  surface.ConfigVerification,
  surface.ReferenceSource,
  surface.CryptoMaterialItem,
  surface.Measurement,
  surface.SevSnpMeasurement,
  surface.TdxMeasurement,
  surface.Expected,
  surface.ExpectedSevSnp,
  surface.ExpectedTdx,
  surface.Register,
  surface.VerificationReportJSON,
  surface.VerifiedFactsJSON,
  surface.PartialFactsJSON,
  surface.ExpectedFactsJSON,
  surface.MeasuredFactsJSON,
  surface.StepJSON,
  surface.VerificationMetadataJSON,
  surface.ArtifactVerificationJSON,
  surface.ConfigVerificationJSON,
  surface.MeasurementJSON,
  openaiEntry.RealtimeOptions,
  openaiEntry.OpenAIOptions,
  openaiEntry.OpenAIClientOptions,
  openaiEntry.AttestedHTTPClient,
  openaiEntry.Uploadable,
];
const typeExports: TypeExports | undefined = undefined;
void typeExports;

/**
 * Only the factories build clients: every constructor is private, so a
 * caller who tries fails to compile. Never called; the directives pin the
 * errors under the test typecheck. Untyped construction is refused at
 * runtime, which each client's own tests check.
 */
function privateConstructors(): void {
  // @ts-expect-error The constructor is private; a client comes from EnclaveHTTPClient.create.
  new surface.EnclaveHTTPClient({} as never);
  // @ts-expect-error The constructor is private; a client comes from RouterHTTPClient.create.
  new surface.RouterHTTPClient({} as never);
  // @ts-expect-error The constructor is private; a client comes from GatewayHTTPClient.create.
  new surface.GatewayHTTPClient({} as never);
  // @ts-expect-error The constructor is private; a client comes from UnverifiedClient.create.
  new unsafeEntry.UnverifiedClient({} as never);
}
void privateConstructors;

const descriptorsOf = (cls: { prototype: object }): [string, PropertyDescriptor][] =>
  Object.getOwnPropertyNames(cls.prototype)
    .filter((n) => n !== "constructor")
    .map((n) => [n, Object.getOwnPropertyDescriptor(cls.prototype, n)!]);
const methodsOf = (cls: { prototype: object }): string[] =>
  descriptorsOf(cls)
    .filter(([, d]) => typeof d.value === "function")
    .map(([n]) => n)
    .sort();
const gettersOf = (cls: { prototype: object }): string[] =>
  descriptorsOf(cls)
    .filter(([, d]) => d.get !== undefined)
    .map(([n]) => n)
    .sort();
const named = (members: Record<string, string>, kind: string): string[] =>
  Object.entries(members)
    .filter(([, k]) => k === kind)
    .map(([n]) => n)
    .sort();

/** The prototype of `cls` carries exactly the getters and methods of `members`; its properties are own, so absent from it. */
function expectShape(cls: { prototype: object }, members: Record<string, string>): void {
  expect(methodsOf(cls)).toEqual(named(members, "method"));
  expect(gettersOf(cls)).toEqual(named(members, "getter"));
  for (const property of named(members, "property")) expect(Object.prototype.hasOwnProperty.call(cls.prototype, property), property).toBe(false);
}

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
  "src/gateway-client.ts": ["GatewayHTTPClient", "fetchCatalog"],
  "src/options.ts": ["GatewayOptions", "ModelPin", "CatalogEntry", "Catalog", "ReplicaVerification"],
};

/** The doc comment that ends right before the export of `name` in `source`, or undefined when there is none. */
function docCommentOf(source: string, name: string): string | undefined {
  const declaration = new RegExp(`\\n(?:/\\*\\*[\\s\\S]*?\\*/\\n)?export (?:async )?(?:class|function|interface|type|const) ${name}\\b`);
  const match = declaration.exec(source);
  return match?.[0].includes("/**") ? match[0] : undefined;
}

/** The `tinfoil/ai-sdk` entry: the AI SDK provider alone, so the AI SDK stays out of bundles that don't use it. */
const AI_SDK_EXPORTS = ["createTinfoil"];
type AiSdkTypeExports = [aiSdk.TinfoilProvider, aiSdk.TinfoilProviderOptions, aiSdk.TinfoilProviderBaseOptions, aiSdk.TinfoilProviderEnclave];
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
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, Record<string, string>> };
    expect(pkg.exports["./ai-sdk"]).toEqual({ types: "./dist/ai-sdk.d.ts", import: "./dist/ai-sdk.js", default: "./dist/ai-sdk.js" });
  });
});

describe("public surface", () => {
  it("documents the experimental exports as such", () => {
    for (const [file, names] of Object.entries(EXPERIMENTAL_EXPORTS)) {
      const source = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
      for (const name of names) {
        expect(docCommentOf(source, name), `${name} in ${file}`).toMatch(/@experimental/);
      }
    }
    expect(Object.values(EXPERIMENTAL_EXPORTS).flat().filter((n) => n in surface).sort()).toEqual(["GatewayHTTPClient", "fetchCatalog"]);
  });

  it("exports exactly the specified names from both entries", () => {
    expect(Object.keys(surface).sort()).toEqual(EXPORTS);
    expect(Object.keys(browser).sort()).toEqual(EXPORTS);
    expect(Object.keys(openaiEntry).sort()).toEqual(OPENAI_EXPORTS);
  });

  it("publishes the OpenAI client as its own subpath, with openai an optional peer dependency", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      exports: Record<string, Record<string, string>>;
      dependencies: Record<string, string>;
      peerDependencies: Record<string, string>;
      peerDependenciesMeta: Record<string, { optional?: boolean }>;
    };
    expect(pkg.exports["./openai"]).toEqual({ types: "./dist/openai.d.ts", import: "./dist/openai.js", default: "./dist/openai.js" });
    expect(pkg.dependencies).not.toHaveProperty("openai");
    expect(pkg.peerDependencies).toHaveProperty("openai");
    expect(pkg.peerDependenciesMeta["openai"]).toEqual({ optional: true });
  });

  it("keeps the unsafe entry to the unverified client, its warning and its options type", () => {
    expect(Object.keys(unsafeEntry).sort()).toEqual(["UNVERIFIED_WARNING", "UnverifiedClient"]);
    expect(unsafeEntry.UNVERIFIED_WARNING).toMatch(/insecure/i);
    expect(staticsOf(unsafeEntry.UnverifiedClient)).toEqual(["create"]);
    expectShape(unsafeEntry.UnverifiedClient, UNVERIFIED_CLIENT_MEMBERS);
    const options: unsafeEntry.UnverifiedOptions | undefined = undefined;
    void options;
  });

  it("shapes the HTTP clients as specified: a `create` factory, state as properties, and the verification methods", () => {
    for (const cls of [surface.EnclaveHTTPClient, surface.RouterHTTPClient]) expect(staticsOf(cls)).toEqual(["create"]);
    expectShape(surface.EnclaveHTTPClient, ENCLAVE_CLIENT_MEMBERS);
    expectShape(surface.RouterHTTPClient, ROUTER_CLIENT_MEMBERS);
    expect(staticsOf(surface.GatewayHTTPClient)).toEqual(["create"]);
    expectShape(surface.GatewayHTTPClient, GATEWAY_CLIENT_MEMBERS);
  });

  it("disposes the HTTP clients and the OpenAI clients over them with `await using`", () => {
    for (const cls of [surface.EnclaveHTTPClient, surface.RouterHTTPClient, surface.GatewayHTTPClient, openaiEntry.OpenAIClient]) {
      expect(typeof (cls.prototype as AsyncDisposable)[Symbol.asyncDispose], cls.name).toBe("function");
    }
    expect(Symbol.asyncDispose in OpenAI.prototype).toBe(false);
    expect(Symbol.asyncDispose in unsafeEntry.UnverifiedClient.prototype).toBe(false);
  });

  it("shapes the OpenAI client as an OpenAI subclass with a public constructor and an `httpClient` property", () => {
    expect(Object.getPrototypeOf(openaiEntry.OpenAIClient)).toBe(OpenAI);
    expect(staticsOf(openaiEntry.OpenAIClient)).toEqual([]);
    expectShape(openaiEntry.OpenAIClient, OPENAI_CLIENT_MEMBERS);
    // The OpenAI client has no member of that name to collide with.
    expect("httpClient" in OpenAI.prototype).toBe(false);
    expect(typeof openaiEntry.createClient).toBe("function");
    expect(typeof surface.fetchCatalog).toBe("function");
  });

  it("refuses the transport options in withOptions at compile time", () => {
    // Checked by the test typecheck: each call below is a type error, so the clone can't name a transport.
    const attempts = (
      tinfoil: openaiEntry.OpenAIClient,
      enclave: openaiEntry.OpenAIClient<surface.EnclaveHTTPClient>,
      router: openaiEntry.OpenAIClient<surface.RouterHTTPClient>,
      gateway: openaiEntry.OpenAIClient<surface.GatewayHTTPClient>,
    ): void => {
      // @ts-expect-error `baseURL` belongs to the attested transport.
      tinfoil.withOptions({ baseURL: "https://evil.example/" });
      // @ts-expect-error `fetch` belongs to the attested transport.
      tinfoil.withOptions({ fetch: globalThis.fetch });
      // @ts-expect-error `baseURL` belongs to the attested transport.
      enclave.withOptions({ baseURL: "https://evil.example/" });
      // @ts-expect-error `fetch` belongs to the attested transport.
      router.withOptions({ fetch: globalThis.fetch });
      // @ts-expect-error `baseURL` belongs to the attested transport.
      gateway.withOptions({ baseURL: "https://evil.example/" });
      // The other OpenAI options and the bearer token remain accepted.
      tinfoil.withOptions({ timeout: 1, maxRetries: 0, defaultHeaders: { "x-a": "b" }, bearerToken: "t" });
    };
    expect(attempts.length).toBe(4);
  });

  it("refuses the OpenAI options that would choose another transport at compile time", () => {
    // Checked by the test typecheck: each option below is a type error, in the factories and in withOptions.
    const attempts = (tinfoil: openaiEntry.OpenAIClient, http: surface.RouterHTTPClient): void => {
      // @ts-expect-error `dataResidency` would pick a regional base URL over the client's.
      void openaiEntry.createClient({ apiKey: "k", dataResidency: "eu" });
      // @ts-expect-error `provider` would pick a third-party base URL over the client's.
      void new openaiEntry.OpenAIClient(http, {}, { apiKey: "k", provider: {} as never });
      // @ts-expect-error `workloadIdentity` authenticates through OpenAI's own token exchange.
      void new openaiEntry.OpenAIClient(http, {}, { workloadIdentity: {} as never });
      // @ts-expect-error `credential` would use OpenAI's own certificate transport.
      void new openaiEntry.OpenAIClient(http, {}, { credential: {} as never });
      // @ts-expect-error `baseURL` is set by the client; `apiPath` chooses the API path.
      void new openaiEntry.OpenAIClient(http, {}, { baseURL: "https://evil.example/" });
      // @ts-expect-error `x509Transport` would use OpenAI's own certificate transport.
      tinfoil.withOptions({ x509Transport: {} as never });
      // @ts-expect-error The HTTP client must be one of the SDK's.
      void new openaiEntry.OpenAIClient({ fetch: globalThis.fetch, baseURL: "https://evil.example/" });
      // A type that omits them is still a valid argument.
      const options: openaiEntry.OpenAIClientOptions = { apiKey: "k", organization: "o", defaultQuery: { q: "1" }, fetchOptions: {} };
      void openaiEntry.createClient(options);
    };
    expect(attempts.length).toBe(2);
  });

  it("opens WebSockets through functions that take a client, not through client methods", () => {
    for (const fn of [surface.createWebSocket, surface.pinnedWebSocketOptions, openaiEntry.createRealtimeWebSocket]) expect(typeof fn).toBe("function");
    expect(methodsOf(surface.EnclaveHTTPClient)).not.toContain("createWebSocket");
  });

  it("re-exports the verifier's error and report schema version from the verifier that the clients use", async () => {
    const verifier = await import("@tinfoilsh/verifier");
    expect(surface.VerificationError).toBe(verifier.VerificationError);
    expect(browser.VerificationError).toBe(verifier.VerificationError);
    expect(surface.REPORT_SCHEMA_VERSION).toBe(verifier.REPORT_SCHEMA_VERSION);
  });

  it("reports the package version", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
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
    await expect(createEnclaveHTTPClient("", { kind: "repoPin", repo: "tinfoilsh/repo" }, {}, { documentFetch: fetches.fetch })).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "ehbp", proxyURL: "http://proxy.example/" } }, { documentFetch: fetches.fetch })).rejects.toBeInstanceOf(
      surface.ConfigurationError,
    );
    // A proxy on the enclave's own origin is refused before either fetch is called.
    await expect(createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "tinfoilsh/repo" }, { transport: { kind: "ehbp", proxyURL: "https://enclave.example/relay", fetch: fetches.fetch } }, { documentFetch: fetches.fetch })).rejects.toBeInstanceOf(
      surface.ConfigurationError,
    );
    expect(fetches.calls).toBe(0);
  });

  it("checks gateway client options before any network I/O", async () => {
    const fetches = countingFetch();
    const seams = { catalogFetch: fetches.fetch, documentFetch: fetches.fetch };
    await expect(createGatewayHTTPClient({ modelPins: new Map([["m", { repo: "tinfoilsh/m" }]]), url: "http://gateway.example/v1/" }, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(createGatewayHTTPClient({ modelPins: new Map() }, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    // @ts-expect-error A gateway client requires model pins.
    await expect(createGatewayHTTPClient({}, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    expect(fetches.calls).toBe(0);
  });

  it("checks router client options before any network I/O", async () => {
    await expect(surface.RouterHTTPClient.create({ transport: { kind: "ehbp", proxyURL: "https://proxy.example/?" } })).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(surface.RouterHTTPClient.create({ transport: { kind: "ehbp", proxyURL: "http://proxy.example/" } })).rejects.toBeInstanceOf(surface.ConfigurationError);
  });

  it("refuses the OpenAI options that would choose another transport before any network I/O", async () => {
    const fetches = countingFetch();
    const router = { routersFetch: fetches.fetch, documentFetch: fetches.fetch };
    for (const [key, value] of Object.entries(FORBIDDEN_TRANSPORT_OPTIONS)) {
      const failure = createTinfoilClient({ apiKey: "k", [key]: value } as openaiEntry.OpenAIClientOptions, router);
      await expect(failure, key).rejects.toBeInstanceOf(surface.ConfigurationError);
      await expect(failure, key).rejects.toThrow(refusal(key));
    }
    expect(fetches.calls).toBe(0);
  });

  it("refuses anything but one of the SDK's HTTP clients in the OpenAI client, without any network I/O", () => {
    for (const bad of [null, undefined, {}, { fetch: globalThis.fetch, baseURL: "https://evil.example/" }, Object.create(surface.RouterHTTPClient.prototype) as object]) {
      expect(() => new openaiEntry.OpenAIClient(bad as never), String(bad)).toThrow(surface.ConfigurationError);
    }
    expect(() => new openaiEntry.OpenAIClient({} as never)).toThrow(/must be an EnclaveHTTPClient, RouterHTTPClient or GatewayHTTPClient/);
  });

  it("fetches nothing before rejecting router client options", async () => {
    const fetches = countingFetch();
    const seams = { routersFetch: fetches.fetch, documentFetch: fetches.fetch };
    await expect(createRouterHTTPClient({ transport: { kind: "ehbp", proxyURL: "https://proxy.example/#" } }, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(createRouterHTTPClient({ transport: { kind: "ehbp", proxyURL: "http://proxy.example/" } }, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    await expect(createRouterHTTPClient({ transport: { kind: "quic" } as never }, seams)).rejects.toBeInstanceOf(surface.ConfigurationError);
    expect(fetches.calls).toBe(0);
  });
});
