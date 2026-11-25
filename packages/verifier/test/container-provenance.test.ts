/** Tests for the builds that a config requires for its container images. */
import { describe, expect, it } from "vitest";
import { configContainerProvenance, type ContainerProvenance } from "../src/internal/runtime/provenance.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("configContainerProvenance", () => {
  const digest = "ab".repeat(32);
  const other = "cd".repeat(32);
  const imageName = "ghcr.io/tinfoilsh/inference-vllm";
  const image = `"${imageName}@sha256:${digest}"`;
  /** The JSON text of each member of the github requirement. */
  const members = { repository: `"tinfoilsh/inference"`, repository_id: `"902195777"`, workflow: `"containers.yml"`, ref: `"refs/tags/vllm-v*"` };
  const githubOf = (members: Record<string, string>): string =>
    `{${Object.entries(members)
      .map(([name, value]) => `"${name}":${value}`)
      .join(",")}}`;
  const github = githubOf(members);
  const provenance = `{"github":${github}}`;
  const unconstrained = `{"name":"router","image":"example.com/router:latest"}`;
  const container = (image: string, provenance: string): string => `{"name":"model","image":${image},"provenance":${provenance}}`;
  const config = (containers: string): Uint8Array => enc(`{"cvm-version":"0.15.5","containers":${containers}}`);
  const requiring = (image: string, provenance: string): Uint8Array => config(`[${container(image, provenance)}]`);
  /** A config whose github requirement has the given members changed or added. */
  const edited = (change: Record<string, string>): Uint8Array => requiring(image, `{"github":${githubOf({ ...members, ...change })}}`);
  const lacking = (member: string): Uint8Array => requiring(image, `{"github":${githubOf(Object.fromEntries(Object.entries(members).filter(([name]) => name !== member)))}}`);
  const required = (digest: string): ContainerProvenance => ({ digest, repository: "tinfoilsh/inference", repositoryID: "902195777", workflow: "containers.yml", ref: "refs/tags/vllm-v*" });

  it.each<[string, Uint8Array, ContainerProvenance[]]>([
    ["no containers", enc(`{"cvm-version":"0.15.5"}`), []],
    ["a null config", enc("null"), []],
    ["empty containers", config("[]"), []],
    ["no provenance", config(`[${unconstrained},{"image":7}]`), []],
    ["each requirement, in container order", config(`[${unconstrained},${container(image, provenance)},${container(`"@sha256:${other}"`, provenance)}]`), [required(digest), required(other)]],
  ])("reads %s", (_name, config, want) => {
    expect(configContainerProvenance(config)).toEqual(want);
  });

  const UNPARSED = "parsing config containers: ";
  const NOT_OBJECTS = "config containers must be an array of objects";
  const NOT_GITHUB = "containers[0].provenance must hold only github, with only the strings repository, repository_id, workflow and ref";
  const NOT_PINNED = "containers[0].image must end with @sha256: and a lowercase hex digest";
  it.each<[string, Uint8Array, string]>([
    ["not JSON", enc("containers: []\n"), UNPARSED],
    ["trailing data", enc(`{"containers":[]}{}`), UNPARSED],
    ["a config that is not an object", enc("[]"), UNPARSED],
    ["repeated container member", config(`[{"image":${image},"image":${image}}]`), UNPARSED],
    ["containers null", config("null"), NOT_OBJECTS],
    ["containers not an array", config("{}"), NOT_OBJECTS],
    ["container null", config("[null]"), NOT_OBJECTS],
    ["container not an object", config(`["model"]`), NOT_OBJECTS],
    ["provenance null", requiring(image, "null"), NOT_GITHUB],
    ["provenance not an object", requiring(image, `"github"`), NOT_GITHUB],
    ["provenance empty", requiring(image, "{}"), NOT_GITHUB],
    ["unknown kind", requiring(image, `{"gitlab":${github}}`), NOT_GITHUB],
    ["second kind", requiring(image, `{"github":${github},"gitlab":{}}`), NOT_GITHUB],
    ["kind in another case", requiring(image, `{"GitHub":${github}}`), NOT_GITHUB],
    ["github null", requiring(image, `{"github":null}`), NOT_GITHUB],
    ["github not an object", requiring(image, `{"github":"tinfoilsh/inference"}`), NOT_GITHUB],
    ["github without repository", lacking("repository"), NOT_GITHUB],
    ["github without repository_id", lacking("repository_id"), NOT_GITHUB],
    ["github without workflow", lacking("workflow"), NOT_GITHUB],
    ["github without ref", lacking("ref"), NOT_GITHUB],
    ["github unknown member", edited({ environment: `"release"` }), NOT_GITHUB],
    ["github repeated member", requiring(image, `{"github":{"ref":"refs/heads/main",${github.slice(1)}}`), UNPARSED],
    ["github number member", edited({ repository_id: "902195777" }), NOT_GITHUB],
    ["github null member", edited({ ref: "null" }), NOT_GITHUB],
    ["image absent", config(`[{"provenance":${provenance}}]`), NOT_PINNED],
    ["image null", requiring("null", provenance), NOT_PINNED],
    ["image not a string", requiring("7", provenance), "cannot unmarshal JSON number into string"],
    ["image by tag", requiring(`"${imageName}:latest"`, provenance), NOT_PINNED],
    ["image digest alone", requiring(`"${digest}"`, provenance), NOT_PINNED],
    ["image digest uppercase", requiring(`"${imageName}@sha256:${digest.toUpperCase()}"`, provenance), NOT_PINNED],
    ["image digest short", requiring(`"${imageName}@sha256:${digest.slice(1)}"`, provenance), NOT_PINNED],
    ["image digest long", requiring(`"${imageName}@sha256:${digest}a"`, provenance), NOT_PINNED],
    ["image digest not last", requiring(`"${imageName}@sha256:${digest}/"`, provenance), NOT_PINNED],
  ])("rejects %s", (_name, config, wantErr) => {
    expect(() => configContainerProvenance(config)).toThrow(wantErr);
  });
});
