/**
 * Tests for the builds that a config requires for its container images:
 * reading the requirements, checking a build attestation against one, and
 * the verifier's use of both.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CONFIG_ID, CONFIG_V1_FORMAT, FORMAT_V3, ROLE_REFERENCE_VALUES } from "../src/document/collateral/collateral.js";
import { CONTAINER_PROVENANCE_V1_FORMAT } from "../src/document/collateral/container.js";
import { RUNTIME_REPO } from "../src/document/collateral/runtime.js";
import { NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { UsageError, VerificationError, type Layer } from "../src/errors.js";
import { authenticateContainer, refMatches } from "../src/internal/endorsement/container.js";
import { ProvenanceClient } from "../src/internal/endorsement/provenance.js";
import { strictParse } from "../src/internal/json/index.js";
import { ARTIFACT_FORMAT_V2 } from "../src/internal/policy/artifact.js";
import { configContainerProvenance, type ContainerProvenance } from "../src/internal/runtime/provenance.js";
import { Verifier, type ConfigTrust, type Policy } from "../src/verifier.js";
import { b64, buildDocument, type WireEntry } from "./helpers/builder.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha256Hex = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

// The recorded bundle is the published build attestation of the image with
// this digest. Its certificate names the workflow identity
// https://github.com/tinfoilsh/measure-image-action/.github/workflows/build.yml@refs/tags/build-v0.14.2.
const RECORDED_BUNDLE = readFileSync(new URL("./fixtures/sigstore/container-provenance-bundle.json", import.meta.url), "utf8");
const RECORDED: ContainerProvenance = {
  digest: "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1",
  repository: "tinfoilsh/measure-image-action",
  repositoryID: "924941172",
  workflow: "build.yml",
  ref: "refs/tags/build-v*",
};

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

describe("authenticateContainer", () => {
  const authenticate = async (change: Partial<ContainerProvenance>): Promise<void> =>
    authenticateContainer(await ProvenanceClient.default(), strictParse(enc(RECORDED_BUNDLE)), { ...RECORDED, ...change });

  it("authenticates the recorded build attestation", async () => {
    await expect(authenticate({})).resolves.toBeUndefined();
  });

  it.each<[string, Partial<ContainerProvenance>, string]>([
    ["another image", { digest: `00${RECORDED.digest.slice(2)}` }, "does not match expected artifact digest"],
    ["another repository", { repository: "tinfoilsh/measure-image" }, `source repository "`],
    ["another repository ID", { repositoryID: "92494117" }, "source repository ID"],
    ["another workflow", { workflow: "release.yml" }, "workflow identity"],
    ["another ref", { ref: "refs/tags/v*" }, "source ref"],
  ])("rejects it for %s", async (_name, change, wantErr) => {
    await expect(authenticate(change)).rejects.toThrow(wantErr);
  });
});

describe("refMatches", () => {
  it.each<[string, string, string, boolean]>([
    ["literal", "refs/heads/main", "refs/heads/main", true],
    ["literal prefix", "refs/heads/main", "refs/heads/maintenance", false],
    ["literal is not a pattern", "refs/tags/v1.2", "refs/tags/v1x2", false],
    ["fewer segments", "refs/tags/*", "refs/tags", false],
    ["more segments", "refs/tags/*", "refs/tags/v1/extra", false],
    ["alone", "refs/tags/*", "refs/tags/v1.2.3", true],
    ["alone, empty match", "refs/tags/*", "refs/tags/", true],
    ["at the end", "refs/tags/build-v*", "refs/tags/build-v0.14.2", true],
    ["at the end, empty match", "refs/tags/build-v*", "refs/tags/build-v", true],
    ["at the end, another start", "refs/tags/build-v*", "refs/tags/rebuild-v1", false],
    ["at the end, across a separator", "refs/tags/build-v*", "refs/tags/build-v1/2", false],
    ["at the start", "refs/tags/*-rc", "refs/tags/v1-rc", true],
    ["at the start, another end", "refs/tags/*-rc", "refs/tags/v1-rc1", false],
    ["in the middle", "refs/tags/v*-rc", "refs/tags/v1.2-rc", true],
    ["in the middle, empty match", "refs/tags/v*-rc", "refs/tags/v-rc", true],
    ["in the middle, ends overlap", "refs/tags/ab*ba", "refs/tags/aba", false],
    ["several", "refs/tags/v*.*.*", "refs/tags/v1.2.3", true],
    ["several, piece missing", "refs/tags/v*.*.*", "refs/tags/v1.2", false],
    ["several, earliest occurrence", "refs/tags/*ab*ab*", "refs/tags/abab", true],
    ["several, out of order", "refs/tags/*a*b*", "refs/tags/ba", false],
    ["several, adjacent", "refs/tags/v**", "refs/tags/v1", true],
    ["in several segments", "refs/*/v*", "refs/tags/v1", true],
    ["in several segments, across a separator", "refs/*/v*", "refs/remotes/origin/v1", false],
    // A matcher that backtracks does not finish the near miss.
    ["many, near miss", `refs/tags/${"*a".repeat(2000)}*b*`, `refs/tags/${"a".repeat(4000)}`, false],
    ["many, match", `refs/tags/${"*a".repeat(2000)}*b*`, `refs/tags/${"a".repeat(4000)}b`, true],
  ])("%s", (_name, pattern, ref, want) => {
    expect(refMatches(pattern, ref)).toBe(want);
  });
});

// No document here has an authentic quote, so one whose provenance passes is
// rejected at the quote layer.
describe("a verifier whose config requires a container build", () => {
  const nonce = new Uint8Array(NONCE_SIZE).fill(7);
  const register = "cd".repeat(48);
  const zero = "0".repeat(96);
  const manifest = enc(
    JSON.stringify({ version: "v1.2.3", igvm: { format_version: 1, snp_launch: { measurement: register }, tdx_launch: { mrtd: register, rtmr0: zero, rtmr1: zero, rtmr2: zero, rtmr3: zero } } }),
  );
  const platform = enc(JSON.stringify({ format: ARTIFACT_FORMAT_V2, measurements: {}, machines: {}, policies: {} }));
  const policy: Policy = { artifacts: { kind: "embeddedArtifacts", runtime: manifest, platform } };
  const runtime = { repo: RUNTIME_REPO, tag: "v1.2.3", digest: sha256Hex(manifest) };

  /** A config that pins the embedded runtime and runs the recorded image under the given provenance member. */
  const configOf = (provenance: string): Uint8Array =>
    enc(`{"cvm-version":"v1.2.3@sha256:${runtime.digest}","containers":[{"name":"app","image":"ghcr.io/tinfoilsh/measure-image-action@sha256:${RECORDED.digest}","provenance":${provenance}}]}`);
  const builtBy = (workflow: string): string => `{"github":{"repository":"${RECORDED.repository}","repository_id":"${RECORDED.repositoryID}","workflow":"${workflow}","ref":"${RECORDED.ref}"}}`;
  const requiring = configOf(builtBy(RECORDED.workflow));
  const unreadable = configOf(`{"gitlab":{}}`);
  const notJSON = enc("containers: []\n");

  const configEntry = (config: Uint8Array): WireEntry => ({ id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_V1_FORMAT, data: JSON.stringify({ config_base64: b64(config) }) });
  const proof: WireEntry = {
    id: `container:sha256:${RECORDED.digest}`,
    role: ROLE_REFERENCE_VALUES,
    format: CONTAINER_PROVENANCE_V1_FORMAT,
    data: `{"digest":"${RECORDED.digest}","sigstore_bundle":${RECORDED_BUNDLE}}`,
  };
  const authorizer: ConfigTrust = { kind: "configAuthorizer", authorize: () => undefined };
  const embedded: ConfigTrust = { kind: "embeddedConfig", bytes: requiring };
  const reference = (config: Uint8Array): ConfigTrust => ({ kind: "embeddedConfigReference", digest: sha256Hex(config), runtime });

  const NO_ENTRY = `document carries no ${CONTAINER_PROVENANCE_V1_FORMAT} reference-values entry for sha256:${RECORDED.digest}`;
  it.each<[string, ConfigTrust, WireEntry[], Layer, string]>([
    ["authorized, proven", authorizer, [configEntry(requiring), proof], "quote", ""],
    ["authorized, no entry", authorizer, [configEntry(requiring)], "provenance", NO_ENTRY],
    ["authorized, another workflow", authorizer, [configEntry(configOf(builtBy("release.yml"))), proof], "provenance", "container provenance workflow identity"],
    ["authorized, unknown kind", authorizer, [configEntry(unreadable), proof], "provenance", "containers[0].provenance must hold only github"],
    ["embedded, proven", embedded, [proof], "quote", ""],
    ["embedded, no entry", embedded, [], "provenance", NO_ENTRY],
    ["reference, document's bytes, proven", reference(requiring), [configEntry(requiring), proof], "quote", ""],
    ["reference, document's bytes, no entry", reference(requiring), [configEntry(requiring)], "provenance", NO_ENTRY],
    ["reference, document's bytes, not JSON", reference(notJSON), [configEntry(notJSON)], "provenance", "parsing config containers"],
    ["reference, no bytes", reference(requiring), [], "quote", ""],
    ["reference, bytes of another config", reference(requiring), [configEntry(unreadable)], "quote", ""],
  ])("%s", async (_name, trust, collateral, layer, wantErr) => {
    const verifier = await Verifier.create(trust, policy);
    const { bytes } = await buildDocument({ nonce, collateralFormat: FORMAT_V3, collateral }, () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: new Uint8Array(1184).fill(1) }));
    const err = await verifier.verifyV3At(bytes, nonce, {}, new Date()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe(layer);
    expect((err as VerificationError).message).toContain(wantErr);
  });

  it("is not built from an embedded config whose requirements it cannot read", async () => {
    await expect(Verifier.create({ kind: "embeddedConfig", bytes: unreadable }, policy)).rejects.toThrow(UsageError);
  });
});
