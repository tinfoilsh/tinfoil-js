/**
 * The trust argument and the verification policy: how each trust variant
 * becomes the verifier's config trust and pin, what untyped code is refused,
 * and that a policy is checked when a client builds its verifier, before
 * any network I/O.
 */
import { describe, expect, it } from "vitest";
import { createEnclaveHTTPClient } from "../src/enclave-client.js";
import { ConfigurationError } from "../src/errors.js";
import { createGatewayHTTPClient } from "../src/gateway-client.js";
import type { Fetch } from "../src/options.js";
import { createRouterHTTPClient } from "../src/router-client.js";
import { cloneTrust, verifierInputs, type Trust } from "../src/trust.js";
import { PUBLIC_REGISTRY_ID } from "../../verifier/src/index.js";

/** A fetch that counts its calls and never answers, so a test can prove that nothing was fetched. */
function counting(): { fetch: Fetch; calls: number } {
  const state = {
    calls: 0,
    fetch: (async () => {
      state.calls++;
      throw new TypeError("no network in this test");
    }) as Fetch,
  };
  return state;
}

describe("verifierInputs", () => {
  const authorize = (): void => undefined;
  const bytes = new Uint8Array([1, 2, 3]);

  it.each<[string, Trust, ReturnType<typeof verifierInputs>]>([
    ["repoPin", { kind: "repoPin", repo: "org/repo" }, { config: undefined, pin: { repo: "org/repo" } }],
    ["projectPin", { kind: "projectPin", project: "org/project" }, { config: undefined, pin: { project: "org/project" } }],
    [
      "projectPin with registries",
      { kind: "projectPin", project: "org/project", registryIDs: [PUBLIC_REGISTRY_ID] },
      { config: { kind: "registries", ids: [PUBLIC_REGISTRY_ID] }, pin: { project: "org/project" } },
    ],
    ["signedBy", { kind: "signedBy", keys: ["pem"] }, { config: { kind: "configSigningKeys", keys: ["pem"] }, pin: { project: "" } }],
    ["signedBy with a project", { kind: "signedBy", keys: ["pem"], project: "org/project" }, { config: { kind: "configSigningKeys", keys: ["pem"] }, pin: { project: "org/project" } }],
    ["authorizedBy", { kind: "authorizedBy", authorize }, { config: { kind: "configAuthorizer", authorize }, pin: {} }],
    ["embeddedConfig", { kind: "embeddedConfig", name: "/org/project/r1", bytes }, { config: { kind: "embeddedConfig", name: "/org/project/r1", bytes }, pin: {} }],
    ["eitherPin", { kind: "eitherPin", repo: "org/repo", project: "org/project" }, { config: undefined, pin: { repo: "org/repo", project: "org/project" } }],
  ])("converts %s", (_name, trust, want) => {
    expect(verifierInputs(trust)).toEqual(want);
  });

  it("refuses a missing trust, an unknown kind or a missing required member", () => {
    for (const bad of [
      undefined,
      null,
      "org/repo",
      { repo: "org/repo" },
      { kind: "pin", repo: "org/repo" },
      { kind: "repoPin" },
      { kind: "repoPin", repo: "" },
      { kind: "projectPin", project: "" },
      { kind: "projectPin", project: 7 },
      { kind: "eitherPin", repo: "org/repo" },
      { kind: "eitherPin", project: "org/project" },
      { kind: 1n },
      { kind: Symbol("repoPin") },
      { kind: {} },
    ]) {
      expect(() => verifierInputs(bad as unknown as Trust), typeof bad).toThrow(ConfigurationError);
    }
    expect(() => verifierInputs({ kind: "pin" } as unknown as Trust)).toThrow(/trust must have kind/);
  });

  it("passes a signedBy project that isn't a string to the pin check rather than dropping it", () => {
    expect(verifierInputs({ kind: "signedBy", keys: ["pem"], project: null as unknown as string }).pin).toEqual({ project: null });
  });

  it("fails closed on an empty registry list rather than widening trust to the public registry", () => {
    expect(() => verifierInputs({ kind: "projectPin", project: "org/project", registryIDs: [] })).toThrow(/registryIDs must not be empty/);
  });
});

describe("cloneTrust", () => {
  it("shares no array or bytes with the original and freezes the copy", () => {
    const registryIDs = [PUBLIC_REGISTRY_ID];
    const project = cloneTrust({ kind: "projectPin", project: "org/project", registryIDs });
    registryIDs.push("other");
    expect(project).toEqual({ kind: "projectPin", project: "org/project", registryIDs: [PUBLIC_REGISTRY_ID] });
    expect(Object.isFrozen(project)).toBe(true);
    const bytes = new Uint8Array([1]);
    const embedded = cloneTrust({ kind: "embeddedConfig", bytes });
    bytes[0] = 9;
    expect(embedded).toEqual({ kind: "embeddedConfig", bytes: new Uint8Array([1]) });
  });
});

describe("the policy and the trust are checked before any network I/O", () => {
  it("refuses an invalid policy or trust on every route", async () => {
    const documents = counting();
    const repo: Trust = { kind: "repoPin", repo: "tinfoilsh/repo" };
    const failures = [
      () => createEnclaveHTTPClient("enclave.example", repo, { policy: { freshnessMaxAgeMs: -1 } }, { documentFetch: documents.fetch }),
      () => createEnclaveHTTPClient("enclave.example", repo, { policy: { artifacts: { kind: "embedded" } as never } }, { documentFetch: documents.fetch }),
      () => createEnclaveHTTPClient("enclave.example", { kind: "repoPin", repo: "bad repo" }, {}, { documentFetch: documents.fetch }),
      () => createEnclaveHTTPClient("enclave.example", { kind: "signedBy", keys: [] }, {}, { documentFetch: documents.fetch }),
      () => createEnclaveHTTPClient("enclave.example", { kind: "authorizedBy", authorize: "yes" as never }, {}, { documentFetch: documents.fetch }),
      () => createEnclaveHTTPClient("enclave.example", { kind: "embeddedConfig", bytes: new Uint8Array() }, {}, { documentFetch: documents.fetch }),
      () => createEnclaveHTTPClient("enclave.example", { kind: "signedBy", keys: ["not a pem"], project: null as unknown as string }, {}, { documentFetch: documents.fetch }),
      () => createRouterHTTPClient({ policy: { freshnessMaxAgeMs: -1 } }, { routersFetch: documents.fetch, documentFetch: documents.fetch }),
      () => createGatewayHTTPClient({ modelPins: new Map([["m", { repo: "tinfoilsh/m" }]]), policy: { freshnessMaxAgeMs: -1 } }, { catalogFetch: documents.fetch, documentFetch: documents.fetch }),
      // The gateway's policy is checked even when every pin sets its own.
      () => createGatewayHTTPClient({ modelPins: new Map([["m", { repo: "tinfoilsh/m", policy: {} }]]), policy: { freshnessMaxAgeMs: -1 } }, { catalogFetch: documents.fetch, documentFetch: documents.fetch }),
      () => createGatewayHTTPClient({ modelPins: new Map([["m", { repo: "tinfoilsh/m", policy: { freshnessMaxAgeMs: -1 } }]]) }, { catalogFetch: documents.fetch, documentFetch: documents.fetch }),
    ];
    for (const failure of failures) await expect(failure()).rejects.toBeInstanceOf(ConfigurationError);
    expect(documents.calls).toBe(0);
  });

  it("refuses a malformed registry ID through the verifier that it builds", async () => {
    const documents = counting();
    const signed = createEnclaveHTTPClient("enclave.example", { kind: "projectPin", project: "org/project", registryIDs: ["not a registry"] }, {}, { documentFetch: documents.fetch });
    await expect(signed).rejects.toBeInstanceOf(ConfigurationError);
    expect(documents.calls).toBe(0);
  });
});
