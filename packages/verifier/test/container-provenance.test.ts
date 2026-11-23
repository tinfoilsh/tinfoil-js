/**
 * Tests for the build a config can require of a container image: reading
 * the requirements from the config bytes (runtime/provenance.ts).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { configContainerProvenance, type ContainerProvenance } from "../src/internal/runtime/provenance.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

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
