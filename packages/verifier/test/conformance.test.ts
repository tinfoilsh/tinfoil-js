/**
 * Runs the shared tinfoil-conformance v3 fixtures through the adapter.
 *
 * Point TINFOIL_CONFORMANCE_FIXTURES at the suite's vectors/v3 directory (it
 * is searched recursively); the test is skipped when unset or missing. A
 * fixture whose stage the adapter reports as unsupported is skipped. The
 * adapter's own input decoding and the live lane's request decoding are
 * checked without fixtures.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { capabilities, ExitCode, run, Stage, type Measurement } from "../conformance/adapter.js";
import { decodeLiveRequest, isAuthority } from "../conformance/live.js";
import { checkReport, failedStep, type ReportedOutput } from "../conformance/report.js";
import { CONFIG_ID, CONFIG_V1_FORMAT, FORMAT_V2, FORMAT_V3, ROLE_REFERENCE_VALUES } from "../src/document/collateral/collateral.js";
import { CONTAINER_PROVENANCE_V1_FORMAT } from "../src/document/collateral/container.js";
import { NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { b64, buildDocument, type WireEntry } from "./helpers/builder.js";
import { newLog, rootJson } from "./helpers/keyed.js";

interface Fixture {
  id: string;
  stage: string;
  input: unknown;
  expected: {
    accepted: boolean;
    code?: string;
    tls_public_key_fp?: string;
    hpke_public_key?: string;
    code_digest?: string;
    code_measurement?: Measurement;
    enclave_measurement?: Measurement;
    /**
     * When declared, what a full-verify vector expects of the report: the
     * layer of the failed step, and members of the report's JSON form, which
     * the report must have with those values.
     */
    failed_step?: string;
    report?: Record<string, unknown>;
  };
}

function findFixtures(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return findFixtures(p);
    return name.endsWith(".json") ? [p] : [];
  });
}

const dir = process.env.TINFOIL_CONFORMANCE_FIXTURES;
const files = dir && existsSync(dir) ? findFixtures(dir).sort() : [];

describe.skipIf(files.length === 0)("v3 conformance fixtures", () => {
  it.for(files.map((f) => [relative(dir!, f), f] as const))("%s", async ([, file], ctx) => {
    const f = JSON.parse(readFileSync(file, "utf8")) as Fixture;
    const { output, exitCode } = await run(f.stage, f.input);
    if (exitCode === ExitCode.Unsupported) ctx.skip();

    expect(output.accepted).toBe(f.expected.accepted);
    expect(exitCode).toBe(f.expected.accepted ? ExitCode.Accepted : f.expected.code === "MALFORMED_INPUT" ? ExitCode.Malformed : ExitCode.Rejected);
    if (!f.expected.accepted && f.expected.code) {
      expect(output.rejection?.code).toBe(f.expected.code);
    }
    // Every full-verify report must agree with its verdict, and match what the vector declares of it.
    expect(checkReport(output)).toBeUndefined();
    if (f.expected.failed_step) expect(failedStep(output.report)).toBe(f.expected.failed_step);
    // Arrays must match element by element; an object may have members that the vector leaves out.
    if (f.expected.report) expect(output.report).toMatchObject(f.expected.report);
    if (f.expected.accepted) {
      const o = output.outputs ?? {};
      const e = f.expected;
      if (e.tls_public_key_fp) expect(o.tls_public_key_fp).toBe(e.tls_public_key_fp);
      if (e.hpke_public_key) expect(o.hpke_public_key).toBe(e.hpke_public_key);
      if (e.code_digest) expect(o.code_digest).toBe(e.code_digest);
      if (e.code_measurement) expect(o.code_measurement).toEqual(e.code_measurement);
      if (e.enclave_measurement) expect(o.enclave_measurement).toEqual(e.enclave_measurement);
    }
  });
});

describe("the report check", () => {
  /** A report that the mutations below can change; the report's own type is readonly. */
  interface Loose {
    steps: { layer: string; status: string }[];
    verified_facts?: object;
    partial_facts?: { expected?: object; measured?: { cpu_measurement?: object; tls_public_key_fp?: string } };
  }
  const steps = (...statuses: string[]) => statuses.map((status, i) => ({ layer: ["envelope", "provenance", "quote", "policy"][i]!, status }));
  const valid = (): ReportedOutput => {
    const report: Loose = { steps: steps("passed", "failed", "not_run", "not_run"), partial_facts: { measured: { tls_public_key_fp: "a".repeat(64) } } };
    return { stage: Stage.Verify, accepted: false, rejection: { code: "PROVENANCE_REJECTED" }, report: report as unknown as ReportedOutput["report"] };
  };
  const loose = (o: ReportedOutput): Loose => o.report as unknown as Loose;

  it("accepts a consistent report, and rejects each inconsistency", () => {
    expect(checkReport(valid())).toBeUndefined();
    const mutations: Record<string, (o: ReportedOutput) => void> = {
      "wrong layer": (o) => (o.rejection = { code: "QUOTE_REJECTED" }),
      "ran after": (o) => (loose(o).steps[2]!.status = "passed"),
      "expected early": (o) => (loose(o).partial_facts!.expected = {}),
      "no measured": (o) => delete loose(o).partial_facts!.measured,
      "cpu early": (o) => (loose(o).partial_facts!.measured!.cpu_measurement = { platform: "sev-snp" }),
      "three steps": (o) => loose(o).steps.pop(),
      "no partial facts": (o) => delete loose(o).partial_facts,
      "verified facts": (o) => (loose(o).verified_facts = {}),
      accepted: (o) => (o.accepted = true),
      "another stage": (o) => (o.stage = Stage.CheckEnvelope),
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const o = valid();
      mutate(o);
      expect(checkReport(o), name).toBeDefined();
    }
  });
});

describe("input decoding", () => {
  // The seconds that a Date can hold: 8.64e15 milliseconds either side of the epoch.
  const DATE_RANGE_S = 8_640_000_000_000;
  const timestampInput = (verification_time_unix: number) => ({
    schema_version: "1",
    timestamp_response_b64: "AA==",
    timestamp_input_b64: "AA==",
    verification_time_unix,
  });

  it("rejects a clock outside the range that a Date can hold as malformed input", async () => {
    for (const clock of [DATE_RANGE_S + 1, -(DATE_RANGE_S + 1), Number.MAX_SAFE_INTEGER]) {
      const { output, exitCode } = await run(Stage.VerifyTimestamp, timestampInput(clock));
      expect(exitCode).toBe(ExitCode.Malformed);
      expect(output.rejection?.code).toBe("MALFORMED_INPUT");
    }
  });

  it("accepts a clock within that range, so that the stage itself judges the input", async () => {
    for (const clock of [DATE_RANGE_S, -DATE_RANGE_S, 1_700_000_000]) {
      const { output, exitCode } = await run(Stage.VerifyTimestamp, timestampInput(clock));
      expect(exitCode).toBe(ExitCode.Rejected);
      expect(output.rejection?.code).toBe("PROVENANCE_REJECTED");
    }
  });
});

describe("the pin of a full-verify input", () => {
  const nonce = new Uint8Array(NONCE_SIZE);
  const input = async (collateralFormat: string, pin: { repo: string; project?: string | null }) => {
    const { bytes } = await buildDocument({ nonce, collateralFormat }, () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: new Uint8Array(1) }));
    return { schema_version: "1", document_b64: Buffer.from(bytes).toString("base64"), nonce_hex: Buffer.from(nonce).toString("hex"), ...pin };
  };
  const code = async (collateralFormat: string, pin: { repo: string; project?: string | null }) => (await run(Stage.Verify, await input(collateralFormat, pin))).output.rejection?.code;

  it("names each namespace only by its own member", async () => {
    // A repository alone never matches registry collateral, nor a project repository collateral.
    expect(await code(FORMAT_V3, { repo: "org/project" })).toBe("PROVENANCE_REJECTED");
    expect(await code(FORMAT_V3, { repo: "org/project", project: null })).toBe("PROVENANCE_REJECTED");
    expect(await code(FORMAT_V2, { repo: "", project: "org/project" })).toBe("PROVENANCE_REJECTED");
    expect(await code(FORMAT_V3, { repo: "Org/My_Repo", project: "org/project" })).toBe("PROVENANCE_REJECTED");
    expect(await code(FORMAT_V2, { repo: "org/project", project: "not a reference" })).toBe("MALFORMED_INPUT");
    const wrongType = await run(Stage.Verify, { ...(await input(FORMAT_V2, { repo: "org/project" })), project: 7 });
    expect(wrongType.exitCode).toBe(ExitCode.Malformed);
  });
});

describe("the container stage", () => {
  // The recorded bundle is the published build attestation of the image with
  // this digest. It verifies against the embedded production root and meets
  // the recorded requirement.
  const digest = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1";
  const bundle = readFileSync(new URL("./fixtures/sigstore/container-provenance-bundle.json", import.meta.url), "utf8");
  const requiring = (workflow: string): string =>
    `,"provenance":{"github":{"repository":"tinfoilsh/measure-image-action","repository_id":"924941172","workflow":"${workflow}","ref":"refs/tags/build-v*"}}`;
  const proof: WireEntry = { id: `container:sha256:${digest}`, role: ROLE_REFERENCE_VALUES, format: CONTAINER_PROVENANCE_V1_FORMAT, data: `{"digest":"${digest}","sigstore_bundle":${bundle}}` };
  /** An entry that carries a config whose container runs the recorded image and has the given members besides. */
  const config = (members: string): WireEntry => ({
    id: CONFIG_ID,
    role: ROLE_REFERENCE_VALUES,
    format: CONFIG_V1_FORMAT,
    data: JSON.stringify({ config_base64: b64(`{"containers":[{"image":"ghcr.io/tinfoilsh/measure-image-action@sha256:${digest}"${members}}]}`) }),
  });
  const input = async (...collateral: WireEntry[]) => {
    const { bytes } = await buildDocument({ nonce: new Uint8Array(NONCE_SIZE), collateralFormat: FORMAT_V3, collateral }, () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: new Uint8Array(1) }));
    return { schema_version: "1", document_b64: b64(bytes) };
  };
  const ACCEPTED = { exitCode: ExitCode.Accepted, output: { stage: Stage.AuthenticateContainers, accepted: true } };
  const rejected = (code: string, exitCode: number) => ({ exitCode, output: { stage: Stage.AuthenticateContainers, accepted: false, rejection: { code } } });
  const REJECTED = rejected("PROVENANCE_REJECTED", ExitCode.Rejected);

  it.each<[string, () => Promise<object>, object]>([
    ["proven", () => input(config(requiring("build.yml")), proof), ACCEPTED],
    ["no requirement", () => input(config("")), ACCEPTED],
    ["no entry", () => input(config(requiring("build.yml"))), REJECTED],
    ["another workflow", () => input(config(requiring("release.yml")), proof), REJECTED],
    ["unknown kind", () => input(config(`,"provenance":{"gitlab":{}}`), proof), REJECTED],
    ["no config", () => input(proof), REJECTED],
    ["another trusted root", async () => ({ ...(await input(config(requiring("build.yml")), proof)), sigstore_trusted_root_json_b64: b64(JSON.stringify(rootJson([await newLog("ecdsa")]))) }), REJECTED],
    ["undecodable document", async () => ({ schema_version: "1", document_b64: b64("{}") }), rejected("MALFORMED_INPUT", ExitCode.Malformed)],
  ])("%s", async (_name, stageInput, want) => {
    expect(await run(Stage.AuthenticateContainers, await stageInput())).toEqual(want);
  });

  it("is listed among the supported stages", () => {
    expect((capabilities().v3 as { stages_supported: string[] }).stages_supported).toContain(Stage.AuthenticateContainers);
  });
});

describe("live request decoding", () => {
  it("accepts a host in either case, with or without a port", () => {
    for (const host of ["enclave.example.com", "Enclave.Example.COM", "ENCLAVE.EXAMPLE.COM:8443", "example.com:443", "[2001:DB8::1]:8443"]) {
      expect(isAuthority(host), host).toBe(true);
    }
    expect(decodeLiveRequest({ host: "Enclave.Example.COM", repo: "org/repo" })).toEqual({ host: "Enclave.Example.COM", repo: "org/repo", project: "" });
    expect(decodeLiveRequest({ host: "example.com", repo: "org/repo", project: null })).toEqual({ host: "example.com", repo: "org/repo", project: "" });
    expect(decodeLiveRequest({ host: "example.com", repo: "org/repo", project: "" })).toEqual({ host: "example.com", repo: "org/repo", project: "" });
    expect(decodeLiveRequest({ host: "example.com", repo: "org/repo", project: "org/project" })).toEqual({ host: "example.com", repo: "org/repo", project: "org/project" });
    expect(decodeLiveRequest({ host: "example.com", project: "org/project" })).toEqual({ host: "example.com", repo: "", project: "org/project" });
    expect(decodeLiveRequest({ host: "example.com", repo: "", project: "" })).toBeUndefined();
    expect(decodeLiveRequest({ host: "example.com", repo: "org/repo", project: 7 })).toBeUndefined();
  });

  it("rejects anything but a bare authority", () => {
    for (const host of ["", "example.com/", "example.com/path", "user@example.com", "example.com?x=1", "example.com#f", "https://example.com", "Example.com:0443"]) {
      expect(isAuthority(host), host).toBe(false);
      expect(decodeLiveRequest({ host, repo: "org/repo" })).toBeUndefined();
    }
    expect(decodeLiveRequest({ host: "example.com", repo: "" })).toBeUndefined();
  });
});
