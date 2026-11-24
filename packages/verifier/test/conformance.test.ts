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
import { capabilities, ExitCode, run, Stage, type Measurement, type Runtime } from "../conformance/adapter.js";
import { decodeLiveRequest, isAuthority } from "../conformance/live.js";
import { checkReport, failedStep, type Report, type ReportedOutput } from "../conformance/report.js";
import { CONFIG_ID, CONFIG_V1_FORMAT, FORMAT_V2, FORMAT_V3, ROLE_REFERENCE_VALUES } from "../src/document/collateral/collateral.js";
import { NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { b64, buildDocument, type WireEntry } from "./helpers/builder.js";

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
    runtime?: Runtime;
    /**
     * When declared, what a full-verify vector expects of the report: the
     * layer of the failed step, every step's status, and the partial facts.
     */
    failed_step?: string;
    report?: Report;
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
    if (f.expected.report) {
      expect(output.report?.steps).toEqual(f.expected.report.steps);
      expect(output.report?.partial_facts).toEqual(f.expected.report.partial_facts);
    }
    if (f.expected.accepted) {
      const o = output.outputs ?? {};
      const e = f.expected;
      if (e.tls_public_key_fp) expect(o.tls_public_key_fp).toBe(e.tls_public_key_fp);
      if (e.hpke_public_key) expect(o.hpke_public_key).toBe(e.hpke_public_key);
      if (e.code_digest) expect(o.code_digest).toBe(e.code_digest);
      if (e.code_measurement) expect(o.code_measurement).toEqual(e.code_measurement);
      if (e.enclave_measurement) expect(o.enclave_measurement).toEqual(e.enclave_measurement);
      if (e.runtime) expect(o.runtime).toEqual(e.runtime);
    }
  });
});

describe("the report check", () => {
  const steps = (...statuses: string[]) => statuses.map((status, i) => ({ layer: ["envelope", "provenance", "quote", "policy"][i]!, status }));
  const valid = (): ReportedOutput => ({
    stage: Stage.Verify,
    accepted: false,
    rejection: { code: "PROVENANCE_REJECTED" },
    report: { steps: steps("passed", "failed", "not_run", "not_run"), partial_facts: { measured: { tls_public_key_fp: "a".repeat(64) } } },
  });

  it("accepts a consistent report, and rejects each inconsistency", () => {
    expect(checkReport(valid())).toBeUndefined();
    const mutations: Record<string, (o: ReportedOutput) => void> = {
      "wrong layer": (o) => (o.rejection = { code: "QUOTE_REJECTED" }),
      "ran after": (o) => (o.report!.steps[2]!.status = "passed"),
      "expected early": (o) => (o.report!.partial_facts!.expected = {}),
      "no measured": (o) => delete o.report!.partial_facts!.measured,
      "cpu early": (o) => (o.report!.partial_facts!.measured!.cpu_measurement = { type: "t", registers: [] }),
      "three steps": (o) => o.report!.steps.pop(),
      "no partial facts": (o) => delete o.report!.partial_facts,
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

/**
 * The runtime stage reads the pin from the config a document carries: JSON
 * from the first JSON version on, YAML before it.
 */
describe("the runtime stage", () => {
  const digest = "ab".repeat(32);
  const input = async (collateral: WireEntry[]) => {
    const { bytes } = await buildDocument({ nonce: new Uint8Array(NONCE_SIZE), collateralFormat: FORMAT_V3, collateral }, () => ({
      format: SEV_SNP_REPORT_V1_FORMAT,
      report: new TextEncoder().encode("unauthenticated quote"),
    }));
    return { schema_version: "1", document_b64: b64(bytes) };
  };
  const carrying = (config: string) =>
    input([{ id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_V1_FORMAT, data: JSON.stringify({ config_base64: b64(config) }) }]);
  const jsonConfig = `{"cvm-version":"0.15.5-rc.1@sha256:${digest}"}`;
  const yamlConfig = `cvm-version: 0.15.4@sha256:${digest}\n`;

  it.each([
    ["a JSON config", jsonConfig, "v0.15.5-rc.1"],
    ["a YAML config", yamlConfig, "v0.15.4"],
  ])("reads the pin of %s", async (_name, config, tag) => {
    const { output, exitCode } = await run(Stage.ReadConfigRuntime, await carrying(config));
    expect(exitCode).toBe(ExitCode.Accepted);
    expect(output).toEqual({ stage: Stage.ReadConfigRuntime, accepted: true, outputs: { runtime: { repo: "tinfoilsh/cvmimage", tag, digest } } });
  });

  it.each([
    ["YAML for a JSON version", yamlConfig.replace("0.15.4", "0.15.5-rc.1")],
    ["JSON not in its one form", jsonConfig.replace(`":"`, `": "`)],
    ["a config with no pin", "cpus: 2\n"],
  ])("rejects %s", async (_name, config) => {
    const { output, exitCode } = await run(Stage.ReadConfigRuntime, await carrying(config));
    expect(exitCode).toBe(ExitCode.Rejected);
    expect(output).toEqual({ stage: Stage.ReadConfigRuntime, accepted: false, rejection: { code: "PROVENANCE_REJECTED" } });
  });

  it("rejects a document that carries no config", async () => {
    const { output, exitCode } = await run(Stage.ReadConfigRuntime, await input([]));
    expect(exitCode).toBe(ExitCode.Rejected);
    expect(output.rejection?.code).toBe("PROVENANCE_REJECTED");
  });

  it("reports a document that does not decode as malformed input", async () => {
    const { output, exitCode } = await run(Stage.ReadConfigRuntime, { schema_version: "1", document_b64: b64("{}") });
    expect(exitCode).toBe(ExitCode.Malformed);
    expect(output.rejection?.code).toBe("MALFORMED_INPUT");
  });

  it("is advertised", () => {
    expect((capabilities().v3 as { stages_supported: string[] }).stages_supported).toContain(Stage.ReadConfigRuntime);
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
