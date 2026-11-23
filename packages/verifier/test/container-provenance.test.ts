/**
 * Tests for the build a config can require of a container image: reading
 * the requirements from the config bytes (runtime/provenance.ts),
 * authenticating a build attestation against one (endorsement/container.ts),
 * and the verifier rejecting a document that lacks a required one.
 *
 * The recorded bundle under fixtures/sigstore is a published build
 * attestation, signed under the Sigstore public-good root, so it verifies
 * against the embedded trusted root without the network. No test here has a
 * quote that authenticates, so a document that passes the provenance layer
 * is rejected next, at the quote layer.
 */
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { dangerousTestOnlyDecode, dangerousTestOnlyVerifier } from "../conformance/testing.js";
import { CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_ID, CONFIG_V1_FORMAT, FORMAT_V3, NotFoundError, ROLE_REFERENCE_VALUES } from "../src/document/collateral/collateral.js";
import { CONTAINER_PROVENANCE_V1_FORMAT } from "../src/document/collateral/container.js";
import { NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { VerificationError } from "../src/errors.js";
import { sha256, toHex } from "../src/internal/bytes.js";
import { CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2, IN_TOTO_STATEMENT_V1, REGISTRY_ID_PREFIX } from "../src/internal/endorsement/approval.js";
import { authenticateContainer, authenticatedContainer, containerIdentity, refMatches } from "../src/internal/endorsement/container.js";
import { ProvenanceClient } from "../src/internal/endorsement/provenance.js";
import { SLSA_PROVENANCE_V1 } from "../src/internal/endorsement/runtime.js";
import { strictParse, type JsonValue } from "../src/internal/json/index.js";
import { ARTIFACT_FORMAT_V2 } from "../src/internal/policy/artifact.js";
import { configContainerProvenance, type ContainerProvenance } from "../src/internal/runtime/provenance.js";
import { GITHUB_OIDC_ISSUER, RUNNER_ENVIRONMENT_GITHUB_HOSTED, type SigningIdentity } from "../src/internal/sigstore/certificate.js";
import { endorsementReference, timestampInput } from "../src/internal/sigstore/timestamp.js";
import { SIGSTORE_TRUSTED_ROOT_JSON } from "../src/trust/sigstore-trusted-root.js";
import type { ContainerVerification } from "../src/verification.js";
import { resolveContainers, type ConfigTrust } from "../src/verifier.js";
import { b64, buildDocument, type WireEntry } from "./helpers/builder.js";
import { build, newLog, newSigner, rootJson, toJson } from "./helpers/keyed.js";
import { newRegistry, registryCertificate } from "./helpers/registry.js";
import { authorityJson, newTimestampAuthority, timestampResponse } from "./helpers/tsa.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/** The recorded bundle is the published build attestation of this image. */
const RECORDED = {
  repository: "tinfoilsh/measure-image-action",
  repositoryID: "924941172",
  workflow: "build.yml",
  digest: "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1",
  ref: "refs/tags/build-v0.14.2",
  commit: "01a05df207140a8e8e1d2cd26028ab7c51dad9d1",
};
const recordedBundle = (): JsonValue => strictParse(new Uint8Array(readFileSync(new URL("./fixtures/sigstore/container-provenance-bundle.json", import.meta.url))));
const recordedRequirement = (): ContainerProvenance => ({
  container: "app",
  digest: RECORDED.digest,
  repository: RECORDED.repository,
  repositoryID: RECORDED.repositoryID,
  workflow: RECORDED.workflow,
  ref: "refs/tags/build-v*",
});

// ---------------------------------------------------------------- requirements in a config

describe("configContainerProvenance", () => {
  const digest = "ab".repeat(32);
  const image = `ghcr.io/tinfoilsh/inference-vllm@sha256:${digest}`;
  const github = `    provenance:
      github:
        repository: tinfoilsh/inference
        repository_id: 902195777
        workflow: containers.yml
        ref: refs/tags/vllm-v*
`;
  const required: ContainerProvenance = {
    container: "model",
    digest,
    repository: "tinfoilsh/inference",
    repositoryID: "902195777",
    workflow: "containers.yml",
    ref: "refs/tags/vllm-v*",
  };
  /** A config whose second container, "model", has the given image and provenance lines. */
  const config = (image: string, provenance: string): Uint8Array =>
    enc(`cvm-version: 0.15.5\ncontainers:\n  - name: router\n    image: example.com/router@sha256:${"cd".repeat(32)}\n  - name: model\n    image: ${image}\n${provenance}`);
  const read = (provenance: string, ofImage = image): ContainerProvenance[] => configContainerProvenance(config(ofImage, provenance));
  /** The provenance lines with one value changed. */
  const replace = (from: string, to: string): string => {
    if (!github.includes(from)) throw new Error(`the provenance lines do not contain ${JSON.stringify(from)}`);
    return github.replace(from, to);
  };

  it("reads the requirement of the container that declares one", () => {
    expect(read(github)).toEqual([required]);
  });

  it.each([[""], ["    provenance:\n"], ["    provenance: null\n"], ["    provenance: ~\n"]])("reads no requirement from %j", (absent) => {
    expect(read(absent)).toEqual([]);
  });

  it("reads requirements in container order, through aliases and flow style", () => {
    const text = `build: &build {repository: tinfoilsh/inference, repository_id: 902195777, workflow: containers.yml, ref: "refs/tags/vllm-v*"}
containers:
  - {name: first, image: "${image}", provenance: {github: *build}}
  - name: plain
    image: example.com/plain:latest
  - name: second
    image: example.com/second@sha256:${"ef".repeat(32)}
    provenance:
      github: *build
`;
    expect(configContainerProvenance(enc(text))).toEqual([
      { ...required, container: "first" },
      { ...required, container: "second", digest: "ef".repeat(32) },
    ]);
  });

  it("reads an alias as the last node anchored under its name before it", () => {
    const text = `first: &repository tinfoilsh/first
second: &repository tinfoilsh/inference
containers:
  - name: model
    image: ${image}
    provenance: {github: {repository: *repository, repository_id: 902195777, workflow: containers.yml, ref: "refs/tags/vllm-v*"}}
third: &repository tinfoilsh/third
`;
    expect(configContainerProvenance(enc(text))).toEqual([required]);
  });

  it.each<[string, string, string, string]>([
    ["unknown kind of requirement", image, "    provenance:\n      gitlab:\n        project: a/b\n", 'containers[1].provenance has unknown field "gitlab"'],
    ["extra requirement", image, github + "      require_signed_commits: true\n", 'containers[1].provenance has unknown field "require_signed_commits"'],
    ["extra detail", image, github + "        environment: release\n", 'containers[1].provenance.github has unknown field "environment"'],
    ["empty requirement", image, "    provenance: {}\n", "containers[1].provenance.github is required"],
    ["not a mapping", image, "    provenance: tinfoilsh/inference\n", "containers[1].provenance must be a mapping"],
    ["kind that is not a mapping", image, "    provenance:\n      github: tinfoilsh/inference\n", "containers[1].provenance.github must be a mapping"],
    ["duplicate detail", image, github + "        ref: refs/heads/main\n", 'containers[1].provenance.github has duplicate field "ref"'],
    ["duplicate kind", image, github + "      github: {}\n", 'containers[1].provenance has duplicate field "github"'],
    ["repository without owner", image, replace("tinfoilsh/inference", "inference"), 'containers[1].provenance.github.repository "inference" must be owner/name'],
    ["missing repository ID", image, replace("        repository_id: 902195777\n", ""), "containers[1].provenance.github.repository_id must be the repository's numeric ID"],
    ["workflow path", image, replace("containers.yml", "sub/containers.yml"), 'containers[1].provenance.github.workflow "sub/containers.yml" must be a workflow file name'],
    ["pull request ref", image, replace("refs/tags/vllm-v*", "refs/pull/*/merge"), 'containers[1].provenance.github.ref "refs/pull/*/merge" must be a tag or branch ref pattern'],
    ["ref with identity separator", image, replace("refs/tags/vllm-v*", "refs/tags/v@refs/heads/main"), "must be a tag or branch ref pattern"],
    ["ref with a trailing newline", image, replace("refs/tags/vllm-v*", '"refs/tags/vllm-v*\\n"'), "must be a tag or branch ref pattern"],
    ["workflow with a trailing newline", image, replace("containers.yml", '"containers.yml\\n"'), "must be a workflow file name"],
    ["repository with a trailing newline", image, replace("tinfoilsh/inference", '"tinfoilsh/inference\\n"'), "must be owner/name"],
    ["image without digest", "ghcr.io/tinfoilsh/inference-vllm:latest", github, "containers[1].image must pin a SHA-256 digest to declare provenance"],
    ["image with two digests", `${image}@sha256:${"ef".repeat(32)}`, github, "containers[1].image must pin a SHA-256 digest to declare provenance"],
    ["image without a name", `"@sha256:${digest}"`, github, "containers[1].image must pin a SHA-256 digest to declare provenance"],
    ["image with a trailing newline", `"${image}\\n"`, github, "containers[1].image must pin a SHA-256 digest to declare provenance"],
    ["image with an uppercase digest", image.replace(digest, digest.toUpperCase()), github, "containers[1].image must pin a SHA-256 digest to declare provenance"],
    ["oversized ref", image, replace("refs/tags/vllm-v*", "refs/tags/" + "*".repeat(300)), "must be a tag or branch ref pattern"],
    ["oversized repository", image, replace("tinfoilsh/inference", "tinfoilsh/" + "a".repeat(200)), "must be owner/name"],
    ["oversized workflow", image, replace("containers.yml", "a".repeat(300) + ".yml"), "must be a workflow file name"],
    ["second document", image, github + "---\ncontainers: []\n", "config must contain exactly one YAML document"],
  ])("rejects %s", (_name, ofImage, provenance, want) => {
    expect(() => read(provenance, ofImage)).toThrow(want);
  });

  it("holds each value to its length bound", () => {
    expect(read(replace("refs/tags/vllm-v*", "refs/tags/" + "a".repeat(245)))).toHaveLength(1);
    expect(() => read(replace("refs/tags/vllm-v*", "refs/tags/" + "a".repeat(246)))).toThrow("must be a tag or branch ref pattern");
    expect(read(replace("tinfoilsh/inference", "o/" + "a".repeat(138)))).toHaveLength(1);
    expect(() => read(replace("tinfoilsh/inference", "o/" + "a".repeat(139)))).toThrow("must be owner/name");
    expect(read(replace("containers.yml", "a".repeat(251) + ".yml"))).toHaveLength(1);
    expect(() => read(replace("containers.yml", "a".repeat(252) + ".yml"))).toThrow("must be a workflow file name");
  });

  // The ID is compared with a certificate as text, so only its one decimal spelling is read.
  it.each([["0"], ["-5"], ["+5"], ["0755"], ["0x10"], ["0o17"], ["1_000"], ["5.0"], ["5.5"], ["1e3"], ['"5"'], ["!!int 5"], ["9223372036854775808"], ["10000000000000000000"], ["1" + "0".repeat(40)], ["true"], ["[5]"], ["~"]])(
    "rejects the repository ID %s",
    (id) => {
      expect(() => read(replace("902195777", id))).toThrow("containers[1].provenance.github.repository_id must be the repository's numeric ID");
    },
  );

  it.each([["1"], ["999999999999999999"], ["9223372036854775807"]])("reads the repository ID %s as written", (id) => {
    expect(read(replace("902195777", id))).toEqual([{ ...required, repositoryID: id }]);
  });

  describe("rejects a config whose requirements it cannot read in full", () => {
    const requirement = "{github: {repository: tinfoilsh/inference, repository_id: 902195777, workflow: containers.yml, ref: refs/tags/v1}}";
    it.each<[string, string, string | RegExp]>([
      // A mapping that combines a non-scalar key with a merge key crashes some YAML decoders.
      ["a sequence key beside a merge key", "? [a]\n: 1\n<<: {b: 2}\ncontainers: []\n", "parsing config provenance: config has a key that is not an untagged scalar"],
      ["a merge key beside a sequence key", "<<: {b: 2}\n? [a]\n: 1\n", "parsing config provenance: config has a merge key, which is not supported"],
      ["a mapping key beside a merge key", "? {a: 1}\n: 1\n<<: {b: 2}\n", "parsing config provenance: config has a key that is not an untagged scalar"],
      ["containers supplied by a merge key", `<<: {containers: [{name: app, image: "${image}", provenance: ${requirement}}]}\n`, "config has a merge key"],
      ["a requirement supplied by a merge key", `base: &base\n  provenance: ${requirement}\ncontainers:\n  - <<: *base\n    name: app\n    image: ${image}\n`, "containers[0] has a merge key"],
      ["a requirement under an alias key", `key: &key provenance\ncontainers:\n  - name: app\n    image: ${image}\n    *key : ${requirement}\n`, "containers[0] has a key that is not an untagged scalar"],
      ["a requirement under a tagged key", `containers:\n  - name: app\n    image: ${image}\n    !!binary cHJvdmVuYW5jZQ==: ${requirement}\n`, "containers[0] has a key that is not an untagged scalar"],
      ["containers under a tagged key", `!!binary Y29udGFpbmVycw==:\n  - name: app\n    image: ${image}\n    provenance: ${requirement}\n`, "config has a key that is not an untagged scalar"],
      ["a repeated requirement", `containers:\n  - name: app\n    image: ${image}\n    provenance: ~\n    provenance: ${requirement}\n`, 'containers[0] mapping key "provenance" already defined'],
      ["repeated containers", `containers: []\ncontainers:\n  - name: app\n    image: ${image}\n    provenance: ${requirement}\n`, 'config mapping key "containers" already defined'],
      ["a requirement under an unknown anchor", `containers:\n  - name: app\n    image: ${image}\n    provenance: *missing\n`, 'parsing config provenance: unknown anchor "missing" referenced'],
      ["an unknown anchor outside the requirements", "containers:\n  - name: app\n    image: example.com/app\n    env: *missing\n", 'parsing config provenance: unknown anchor "missing" referenced'],
      ["an alias before its anchor", "containers:\n  - name: *later\n    image: example.com/app\nlater: &later app\n", 'parsing config provenance: unknown anchor "later" referenced'],
      ["containers that are not a sequence", "containers: {name: app}\n", "parsing config provenance: containers must be a sequence"],
      ["a container that is not a mapping", "containers:\n  - app\n", "parsing config provenance: containers[0] must be a mapping"],
      ["an image that is not a scalar", "containers:\n  - name: app\n    image: [a]\n", "parsing config provenance: containers[0].image must be a scalar"],
      ["a config that is not a mapping", "- containers\n", "parsing config provenance: config is not a mapping"],
      ["an empty config", "", "parsing config provenance: EOF"],
      ["invalid YAML", "containers: [\n", /^parsing config provenance: /],
      ["a tab-indented line", "containers:\n\t- name: app\n", /^parsing config provenance: /],
    ])("%s", (_name, text, want) => {
      expect(() => configContainerProvenance(enc(text))).toThrow(want);
    });

    it("invalid UTF-8", () => {
      expect(() => configContainerProvenance(new Uint8Array([...enc("containers: "), 0xff, 0x0a]))).toThrow("parsing config provenance: config is not valid UTF-8");
    });

    // A null tag does not make a mapping absent.
    it("reads a requirement that is tagged as null", () => {
      const text = `containers:\n  - name: model\n    image: ${image}\n    provenance: !!null {github: {repository: tinfoilsh/inference, repository_id: 902195777, workflow: containers.yml, ref: "refs/tags/vllm-v*"}}\n`;
      expect(configContainerProvenance(enc(text))).toEqual([required]);
    });
  });

  describe("when the YAML parser throws", () => {
    afterEach(() => {
      vi.doUnmock("yaml");
      vi.resetModules();
    });

    it("reports a parse failure", async () => {
      vi.resetModules();
      vi.doMock("yaml", async (importOriginal) => ({
        ...(await importOriginal<typeof import("yaml")>()),
        parseAllDocuments: () => {
          throw new RangeError("Maximum call stack size exceeded");
        },
      }));
      const reader = await import("../src/internal/runtime/provenance.js");
      expect(() => reader.configContainerProvenance(config(image, github))).toThrow("parsing config provenance: Maximum call stack size exceeded");
    });
  });
});

// ---------------------------------------------------------------- build attestations

describe("authenticateContainer", () => {
  let client: ProvenanceClient;
  beforeAll(async () => {
    client = await ProvenanceClient.default();
  });

  it("authenticates the recorded build attestation under the embedded trusted root", async () => {
    const container = { digest: RECORDED.digest, repository: RECORDED.repository, workflow: RECORDED.workflow, ref: RECORDED.ref, commit: RECORDED.commit };
    expect(await authenticateContainer(client, recordedBundle(), recordedRequirement())).toEqual(container);
    expect(await authenticateContainer(client, recordedBundle(), { ...recordedRequirement(), ref: RECORDED.ref })).toEqual(container);
  });

  it.each<[string, Partial<ContainerProvenance>, RegExp]>([
    ["another image", { digest: "00" + RECORDED.digest.slice(2) }, /^verifying container provenance: .*does not match expected artifact digest/],
    ["another repository", { repository: "tinfoilsh/cvmimage" }, /^verifying container provenance: .*signing identity/],
    ["a repository prefix", { repository: "tinfoilsh/measure-image" }, /^verifying container provenance: .*signing identity/],
    ["another repository ID", { repositoryID: "902195777" }, /^container provenance source repository ID does not match/],
    ["another workflow", { workflow: "release.yml" }, /^verifying container provenance: .*signing identity/],
    ["a workflow prefix", { workflow: "build.ym" }, /^verifying container provenance: .*signing identity/],
    ["another tag series", { ref: "refs/tags/v*" }, /^verifying container provenance: .*signing identity/],
    ["an exact other tag", { ref: "refs/tags/build-v0.14.3" }, /^verifying container provenance: .*signing identity/],
    ["a branch", { ref: "refs/heads/main" }, /^verifying container provenance: .*signing identity/],
  ])("rejects the recorded attestation for %s", async (_name, change, want) => {
    await expect(authenticateContainer(client, recordedBundle(), { ...recordedRequirement(), ...change })).rejects.toThrow(want);
  });
});

describe("authenticatedContainer", () => {
  type Claims = { -readonly [K in keyof SigningIdentity]: SigningIdentity[K] };
  interface Statement {
    _type: string;
    subject: unknown[];
    predicateType: string;
    predicate?: unknown;
  }
  const required = recordedRequirement();
  /** A verified bundle whose claims and statement meet the requirement, then changed. */
  const verified = (change: (claims: Claims, statement: Statement) => void = () => undefined): { identity: SigningIdentity; payload: Uint8Array } => {
    const identity: Claims = {
      subjectAlternativeName: `https://github.com/${RECORDED.repository}/.github/workflows/${RECORDED.workflow}@${RECORDED.ref}`,
      issuer: GITHUB_OIDC_ISSUER,
      runnerEnvironment: RUNNER_ENVIRONMENT_GITHUB_HOSTED,
      sourceRepositoryURI: `https://github.com/${RECORDED.repository}`,
      sourceRepositoryIdentifier: RECORDED.repositoryID,
      sourceRepositoryOwnerIdentifier: "",
      sourceRepositoryRef: RECORDED.ref,
      sourceRepositoryDigest: RECORDED.commit,
    };
    const statement: Statement = {
      _type: IN_TOTO_STATEMENT_V1,
      subject: [{ name: "ghcr.io/tinfoilsh/measure-image-action", digest: { sha256: RECORDED.digest } }],
      predicateType: SLSA_PROVENANCE_V1,
      predicate: {},
    };
    change(identity, statement);
    return { identity, payload: enc(JSON.stringify(statement)) };
  };

  it("reports the ref and commit the signing certificate states", () => {
    expect(authenticatedContainer(verified(), required)).toEqual({
      digest: RECORDED.digest,
      repository: RECORDED.repository,
      workflow: RECORDED.workflow,
      ref: RECORDED.ref,
      commit: RECORDED.commit,
    });
  });

  it.each<[string, (claims: Claims, statement: Statement) => void, string]>([
    // A workflow in another repository can call the required workflow file, which then signs with its own identity.
    ["a run called from another repository", (c) => (c.sourceRepositoryURI = "https://github.com/attacker/fork"), 'source repository "https://github.com/attacker/fork" does not match'],
    ["a source repository with a trailing newline", (c) => (c.sourceRepositoryURI += "\n"), "source repository"],
    ["a recreated repository", (c) => (c.sourceRepositoryIdentifier = "1"), "source repository ID does not match"],
    ["a missing repository ID", (c) => (c.sourceRepositoryIdentifier = ""), "source repository ID does not match"],
    ["a pull request ref", (c) => (c.sourceRepositoryRef = "refs/pull/7/merge"), 'source ref "refs/pull/7/merge" does not match "refs/tags/build-v*"'],
    ["a nested tag", (c) => (c.sourceRepositoryRef = "refs/tags/build-v1/extra"), "source ref"],
    ["a missing ref", (c) => (c.sourceRepositoryRef = ""), "source ref"],
    ["a missing commit", (c) => (c.sourceRepositoryDigest = ""), "source digest is not a lowercase Git commit"],
    ["an uppercase commit", (c) => (c.sourceRepositoryDigest = RECORDED.commit.toUpperCase()), "source digest is not a lowercase Git commit"],
    ["a commit with a trailing newline", (c) => (c.sourceRepositoryDigest += "\n"), "source digest is not a lowercase Git commit"],
    ["another predicate", (_c, s) => (s.predicateType = "https://spdx.dev/Document/v2.3"), "container provenance must use SLSA v1"],
    ["another statement type", (_c, s) => (s._type = "https://in-toto.io/Statement/v0.1"), "container provenance must use SLSA v1"],
    ["a statement without a predicate", (_c, s) => delete s.predicate, "container provenance predicate is not an object"],
  ])("rejects %s", (_name, change, want) => {
    expect(() => authenticatedContainer(verified(change), required)).toThrow(want);
  });

  it("rejects a payload that is not a statement", () => {
    expect(() => authenticatedContainer({ ...verified(), payload: enc("null") }, required)).toThrow("container provenance must use SLSA v1");
    expect(() => authenticatedContainer({ ...verified(), payload: enc("not json") }, required)).toThrow();
  });
});

describe("container signing identities", () => {
  const prefix = "https://github.com/tinfoilsh/inference/.github/workflows/containers.yml@";
  const identity = (ref: string, repository = "tinfoilsh/inference", workflow = "containers.yml") =>
    containerIdentity({ container: "", digest: "", repository, repositoryID: "", workflow, ref });

  it.each<[string, string, boolean]>([
    ["refs/tags/vllm-v*", "refs/tags/vllm-v0.34.0", true],
    ["refs/tags/vllm-v*", "refs/tags/vllm-v", true],
    ["refs/tags/vllm-v*", "refs/tags/omni-v0.34.0", false],
    ["refs/tags/vllm-v*", "refs/tags/vllm-v0/34", false],
    ["refs/tags/vllm-v*", "refs/heads/vllm-v0.34.0", false],
    ["refs/tags/vllm-v*", "refs/tags/vllm-v0.34.0@refs/heads/main", false],
    ["refs/tags/v1.2.3", "refs/tags/v1.2.3", true],
    ["refs/tags/v1.2.3", "refs/tags/v1x2x3", false],
    ["refs/tags/v1.2.3", "refs/tags/v1.2.3\n", false],
    ["refs/tags/v1.2.3", "refs/tags/v1.2.34", false],
    ["refs/heads/main", "refs/heads/main", true],
    ["refs/heads/main", "refs/heads/maintenance", false],
    ["refs/heads/main", "refs/heads/mai", false],
    ["refs/heads/release/*", "refs/heads/release/2026", true],
    ["refs/heads/release/*", "refs/heads/release/2026/hotfix", false],
    ["refs/heads/*/stable", "refs/heads/2026/stable", true],
    ["refs/heads/*/stable", "refs/heads/2026/04/stable", false],
    ["refs/tags/*-v*", "refs/tags/vllm-v0.34.0", true],
    ["refs/tags/*-v*", "refs/tags/a-v-v1-v2", true],
    ["refs/tags/*-v*", "refs/tags/vllm0.34.0", false],
    ["refs/tags/*-v*.0", "refs/tags/vllm-v0.34.0.1", false],
    ["refs/tags/v*", "refs/tags/v*", true],
  ])("the pattern %s matching %j is %s", (pattern, ref, want) => {
    expect(refMatches(pattern, ref)).toBe(want);
    expect(identity(pattern).test(prefix + ref)).toBe(want);
  });

  it("takes the repository and workflow as literals and matches the whole identity", () => {
    const tagged = identity("refs/tags/v*");
    expect(tagged.test(prefix + "refs/tags/v1")).toBe(true);
    expect(tagged.test("x" + prefix + "refs/tags/v1")).toBe(false);
    // A wildcard takes any character but "/" and "@", a newline included.
    expect(tagged.test(prefix + "refs/tags/v1\n")).toBe(true);
    expect(tagged.test(prefix + "refs/tags/v1\nhttps://github.com/other")).toBe(false);
    expect(tagged.test(prefix.replace("containers.yml", "containersXyml") + "refs/tags/v1")).toBe(false);
    expect(tagged.test(prefix.replace("containers.yml", "sub/containers.yml") + "refs/tags/v1")).toBe(false);
    expect(tagged.test(prefix.replace("tinfoilsh/inference", "tinfoilsh/inference2") + "refs/tags/v1")).toBe(false);
    const dotted = identity("refs/heads/main", "tinfoilsh/a.b", "c+d.yml");
    expect(dotted.test("https://github.com/tinfoilsh/a.b/.github/workflows/c+d.yml@refs/heads/main")).toBe(true);
    expect(dotted.test("https://github.com/tinfoilsh/aXb/.github/workflows/c+d.yml@refs/heads/main")).toBe(false);
    expect(dotted.test("https://github.com/tinfoilsh/a.b/.github/workflows/ccd.yml@refs/heads/main")).toBe(false);
  });

  it("agrees with the anchored regular expression on every short pattern and ref", () => {
    /** Every string over `alphabet` of at most `max` characters. */
    const strings = (alphabet: string, max: number): string[] => {
      const all = [""];
      for (let from = 0, length = 0; length < max; length++) {
        const to = all.length;
        for (let i = from; i < to; i++) for (const c of alphabet) all.push(all[i]! + c);
        from = to;
      }
      return all;
    };
    const literal = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const refs = strings("ab/@\n", 5);
    const disagreements: string[] = [];
    for (const pattern of strings("ab*/@", 4)) {
      const expression = new RegExp(`^(?:${pattern.split("*").map(literal).join("[^/@]*")})$`);
      for (const ref of refs) {
        if (refMatches(pattern, ref) !== expression.test(ref)) disagreements.push(`${JSON.stringify(pattern)} against ${JSON.stringify(ref)}`);
      }
    }
    expect(disagreements).toEqual([]);
  });

  // A backtracking match of this pattern would not finish.
  it("matches a pattern of many wildcards against a long ref", () => {
    const pattern = "refs/tags/" + "*a".repeat(120);
    const run = "a".repeat(20_000);
    expect(refMatches(pattern, "refs/tags/" + run)).toBe(true);
    expect(refMatches(pattern, "refs/tags/" + run + "b")).toBe(false);
    expect(identity(pattern).test(prefix + "refs/tags/" + run + "b")).toBe(false);
  });
});

// ---------------------------------------------------------------- verification

describe("a config that requires container provenance", () => {
  const nonce = new Uint8Array(NONCE_SIZE).fill(7);
  const register = "cd".repeat(48);
  const manifest = enc(
    JSON.stringify({
      version: "v1.2.3",
      igvm: { format_version: 1, snp_launch: { measurement: register }, tdx_launch: { mrtd: register, rtmr0: "0".repeat(96), rtmr1: "0".repeat(96), rtmr2: "0".repeat(96), rtmr3: "0".repeat(96) } },
    }),
  );
  const platform = enc(JSON.stringify({ format: ARTIFACT_FORMAT_V2, measurements: {}, machines: {}, policies: {} }));
  const embeddedArtifacts = { artifacts: { kind: "embeddedArtifacts", runtime: manifest, platform } } as const;
  const provenance = `    provenance:
      github:
        repository: ${RECORDED.repository}
        repository_id: ${RECORDED.repositoryID}
        workflow: ${RECORDED.workflow}
        ref: refs/tags/build-v*
`;
  const container = (name: string): string => `  - name: ${name}\n    image: ghcr.io/tinfoilsh/measure-image-action@sha256:${RECORDED.digest}\n`;
  const proof = (id: string, digest: string): WireEntry => ({
    id,
    role: ROLE_REFERENCE_VALUES,
    format: CONTAINER_PROVENANCE_V1_FORMAT,
    data: JSON.stringify({ digest, sigstore_bundle: JSON.parse(readFileSync(new URL("./fixtures/sigstore/container-provenance-bundle.json", import.meta.url), "utf8")) as unknown }),
  });
  /** The config that pins the embedded runtime and declares the given containers. */
  const configOf = async (containers: string): Promise<Uint8Array> => enc(`cvm-version: v1.2.3@sha256:${toHex(await sha256(manifest))}\ncontainers:\n${containers}`);
  const documentOf = async (collateral: WireEntry[]): Promise<Uint8Array> =>
    (await buildDocument({ nonce, collateralFormat: FORMAT_V3, collateral }, () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: new Uint8Array(1184).fill(1) }))).bytes;
  const proven = (name: string): ContainerVerification => ({
    container: name,
    digest: RECORDED.digest,
    repository: RECORDED.repository,
    workflow: RECORDED.workflow,
    ref: RECORDED.ref,
    commit: RECORDED.commit,
  });

  describe("authorized by the caller", () => {
    const plain = async (config: Uint8Array): Promise<WireEntry> => ({ id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_V1_FORMAT, data: JSON.stringify({ config_base64: b64(config) }) });
    /** The rejection of a document that carries the config and the given proofs. */
    const verify = async (containers: string, ...proofs: WireEntry[]): Promise<VerificationError> => {
      const doc = await documentOf([await plain(await configOf(containers)), ...proofs]);
      const verifier = await dangerousTestOnlyVerifier({}, { kind: "configAuthorizer", authorize: () => undefined }, embeddedArtifacts);
      const err = await verifier.verifyV3At(doc, nonce, {}, new Date()).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VerificationError);
      return err as VerificationError;
    };

    it("proves every container that requires a build, and names the ref and commit it ran from", async () => {
      const containers = container("first") + provenance + container("second") + provenance + container("unconstrained");
      const config = await configOf(containers);
      const doc = await dangerousTestOnlyDecode(await documentOf([await plain(config), proof("container", RECORDED.digest)]));
      expect(await resolveContainers(await ProvenanceClient.default(), doc, config)).toEqual([proven("first"), proven("second")]);
      expect((await verify(containers, proof("container", RECORDED.digest))).layer).toBe("quote");
    });

    it("checks nothing for a config that requires no build, or whose bytes the document omits", async () => {
      const doc = await dangerousTestOnlyDecode(await documentOf([]));
      const client = await ProvenanceClient.default();
      expect(await resolveContainers(client, doc, await configOf(container("app")))).toEqual([]);
      expect(await resolveContainers(client, doc, undefined)).toEqual([]);
      expect((await verify(container("app"))).layer).toBe("quote");
    });

    it("rejects a document without the proof", async () => {
      const err = await verify(container("app") + provenance);
      expect(err.layer).toBe("provenance");
      expect(err.message).toContain(`container "app" requires provenance: collateral entry not found`);
      expect((err.cause as { cause?: unknown }).cause).toBeInstanceOf(NotFoundError);
    });

    it("rejects a document whose proof is for another image", async () => {
      const err = await verify(container("app") + provenance, proof("container", "ab".repeat(32)));
      expect(err.layer).toBe("provenance");
      expect(err.message).toContain(`container "app" requires provenance: collateral entry not found`);
    });

    it("rejects a proof from another workflow", async () => {
      const err = await verify(container("app") + provenance.replace(RECORDED.workflow, "release.yml"), proof("container", RECORDED.digest));
      expect(err.layer).toBe("provenance");
      expect(err.message).toContain(`container "app": verifying container provenance`);
    });

    it("rejects a requirement it cannot read", async () => {
      const err = await verify(container("app") + provenance + "      gitlab: {}\n", proof("container", RECORDED.digest));
      expect(err.layer).toBe("provenance");
      expect(err.message).toContain(`containers[0].provenance has unknown field "gitlab"`);
    });
  });

  describe("endorsed by a registry", () => {
    const REGISTRY_ID = REGISTRY_ID_PREFIX + "9c4a7f21e0b836d56a13c8fe42d907ab";
    const GEN_TIME = new Date("2025-06-15T11:00:00Z");
    let roots: { sigstore: Uint8Array; registryRoots: string[] };
    /** The collateral entry of a registry's approval of `config`, with or without the config bytes. */
    let endorsement: (config: Uint8Array, withConfig: boolean) => Promise<WireEntry>;

    beforeAll(async () => {
      const tsa = await newTimestampAuthority();
      const log = await newLog("ecdsa");
      const registry = await newRegistry(GEN_TIME);
      const signer = await newSigner();
      const certificate = await registryCertificate(registry, signer.spki, { registryID: REGISTRY_ID, now: GEN_TIME });
      // The approval is signed under a test log and timestamp authority, and
      // the recorded proof under the public-good root, so the root has both.
      const root = JSON.parse(SIGSTORE_TRUSTED_ROOT_JSON) as { tlogs: unknown[]; timestampAuthorities: unknown[] };
      const test = rootJson([log], [authorityJson(tsa)]) as { tlogs: unknown[]; timestampAuthorities: unknown[] };
      root.tlogs.push(...test.tlogs);
      root.timestampAuthorities.push(...test.timestampAuthorities);
      roots = { sigstore: enc(JSON.stringify(root)), registryRoots: [registry.root.pem] };
      endorsement = async (config, withConfig) => {
        const core = {
          _type: IN_TOTO_STATEMENT_V1,
          subject: [{ name: "/org/project/r1", digest: { sha256: toHex(await sha256(config)) } }],
          predicateType: CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2,
          predicate: { scope: REGISTRY_ID, runtime: { repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: toHex(await sha256(manifest)) } },
        };
        const inner = await timestampResponse(tsa, timestampInput("tinfoil-config-freshness/v2\0", toJson(core)), GEN_TIME);
        const statement = { ...core, predicate: { ...core.predicate, freshness: { rfc3161Timestamp: b64(inner) } } };
        const built = await build(signer, log, { statement, certificate, timestampsFor: async (sig) => [await timestampResponse(tsa, sig, GEN_TIME)] });
        const data = {
          endorsement_ref: await endorsementReference(built.payload),
          ...(withConfig ? { config_base64: b64(config) } : {}),
          sigstore_bundle: built.json,
          issuer_certificate_der: b64(registry.rootDer),
        };
        return { id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_ENDORSEMENT_V2_FORMAT, data: JSON.stringify(data) };
      };
    });

    const verify = async (collateral: WireEntry[]): Promise<VerificationError> => {
      const trust: ConfigTrust = { kind: "registries", ids: [REGISTRY_ID] };
      const verifier = await dangerousTestOnlyVerifier(roots, trust, embeddedArtifacts);
      const err = await verifier.verifyV3At(await documentOf(collateral), nonce, { project: "org/project@r1" }, new Date(GEN_TIME.getTime() + 60 * 60 * 1000)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VerificationError);
      return err as VerificationError;
    };

    it("requires the proof once the endorsed config bytes are in the document", async () => {
      const config = await configOf(container("app") + provenance);
      const missing = await verify([await endorsement(config, true)]);
      expect(missing.layer).toBe("provenance");
      expect(missing.message).toContain(`container "app" requires provenance: collateral entry not found`);
      expect((await verify([await endorsement(config, true), proof("container", RECORDED.digest)])).layer).toBe("quote");
    });

    it("checks nothing when the document omits the config bytes", async () => {
      const config = await configOf(container("app") + provenance);
      expect((await verify([await endorsement(config, false)])).layer).toBe("quote");
    });
  });
});
