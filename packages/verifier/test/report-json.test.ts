/**
 * The report's JSON form, which every Tinfoil SDK exports, checked against
 * the golden files in fixtures/report-json. They come from tinfoil-go
 * (verify/testdata/report-json, tinfoilsh/tinfoil-go#346), and their README
 * describes them. A file that names a conformance vector is checked by
 * verifying that vector through the conformance adapter; the others are
 * built here from the same input that the Go test that wrote them builds.
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { run, Stage } from "../conformance/adapter.js";
import { FORMAT_V3 } from "../src/document/collateral/collateral.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { UsageError, VerificationError } from "../src/errors.js";
import { sha256, toHex } from "../src/internal/bytes.js";
import { ARTIFACT_FORMAT_V2 } from "../src/internal/policy/artifact.js";
import { REPORT_SCHEMA_VERSION, ReportBuilder, type VerificationReport, type VerificationReportJSON } from "../src/report.js";
import { verifiedFactsOf } from "../src/verification.js";
import { Verifier } from "../src/verifier.js";
import { VERIFIER_NAME, VERIFIER_VERSION } from "../src/version.js";
import { buildDocument } from "./helpers/builder.js";
import { conformanceAvailable, loadFixture, vectorsTitle } from "./helpers/conformance.js";

interface Golden {
  description: string;
  vector?: string;
  report: Record<string, unknown>;
}

const GOLDEN_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures/report-json");
const goldens = new Map(
  readdirSync(GOLDEN_DIR)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => [name.replace(/\.json$/, ""), JSON.parse(readFileSync(join(GOLDEN_DIR, name), "utf8")) as Golden] as const),
);
const golden = (name: string): Golden => {
  const g = goldens.get(name);
  if (g === undefined) throw new Error(`no golden file ${name}.json`);
  return g;
};

/** The members of the form that hold a time. */
const TIMES = new Set(["approval_time", "signature_time", "freshness_expires_at", "verified_at"]);
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/**
 * A JSON value in the form that the golden files' comparison rules compare:
 * without step messages, which are each SDK's own text, and without
 * metadata, which describes the run. Times become instants, at the
 * millisecond precision that a Date holds.
 */
function comparable(value: unknown, key = ""): unknown {
  // An element of an array is walked under the array's key, so that a step is walked under "steps".
  if (Array.isArray(value)) return value.map((v) => comparable(v, key));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === "metadata" || (k === "message" && key === "steps")) continue;
      out[k] = comparable(v, k);
    }
    return out;
  }
  if (TIMES.has(key) && typeof value === "string") {
    expect(value).toMatch(RFC3339_UTC);
    return Date.parse(value);
  }
  return value;
}

/** Checks `report`'s JSON form against the golden file `name`, and the rules that the comparison leaves out. */
function expectGolden(name: string, got: unknown): void {
  const json = JSON.parse(JSON.stringify(got)) as Record<string, unknown>;
  expect(comparable(json)).toStrictEqual(comparable(golden(name).report));
  // A message only for a failed or a skipped step, and never "".
  for (const step of json.steps as { status: string; message?: string }[]) {
    if (step.status === "failed" || step.status === "skipped") expect(step.message).toMatch(/./);
    else expect(step).not.toHaveProperty("message");
  }
  expect(json.metadata).toStrictEqual({ verified_at: expect.stringMatching(RFC3339_UTC), verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION } });
  expect(Date.parse((json.metadata as { verified_at: string }).verified_at)).toBe(Date.parse((golden(name).report.metadata as { verified_at: string }).verified_at));
  const values = (v: unknown): unknown[] => (v !== null && typeof v === "object" ? Object.values(v).flatMap(values) : [v]);
  expect(values(json).filter((v) => v === null || v === "")).toEqual([]);
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const rejectionReport = (err: unknown): VerificationReport => {
  expect(err).toBeInstanceOf(VerificationError);
  return (err as VerificationError).report;
};

/** The appraisal instant of the golden cases that Go builds: 2026-01-02T03:04:05+01:00. */
const GOLDEN_AT = new Date("2026-01-02T02:04:05Z");

describe("the report's JSON form, against the golden files", () => {
  it("covers every golden file", () => {
    expect([...goldens.keys()]).toHaveLength(10);
    for (const g of goldens.values()) expect(g.report.schema_version).toBe(REPORT_SCHEMA_VERSION);
  });

  // goldenConfigFacts in tinfoil-go's verify/report_json_test.go. Its times
  // carry 500ns that a Date can't hold, so they compare at millisecond
  // precision.
  it("writes every member of a config-based verification's facts: acceptance-config-facts", () => {
    const launch = new Uint8Array(48);
    launch.set([0xab, 0xcd]);
    const approved = new Date("2026-09-20T03:00:00-05:00");
    const b = new ReportBuilder();
    for (const layer of ["envelope", "provenance", "quote", "policy"] as const) b.passed(layer);
    const report = b.passedAll(
      verifiedFactsOf({
        configRepo: "tinfoilsh/cvmimage",
        codeDigest: "0a".repeat(32),
        codeTag: "v0.15.0",
        codeMeasurement: { platform: "sev-snp", launch },
        enclaveMeasurement: { platform: "sev-snp", launch },
        config: {
          source: "endorsement",
          name: "/org/project/v1",
          digest: "0c".repeat(32),
          reference: "org/project@v1",
          signingKeyHint: "hint",
          approvalTime: approved,
          registryID: "registry",
          signatureTime: new Date(approved.getTime() + 60_000),
        },
        runtime: { source: "endorsement", repo: "tinfoilsh/cvmimage", tag: "v0.15.0", digest: "0a".repeat(32), name: "runtime", commit: "0e".repeat(20), approvalTime: approved },
        platform: { source: "embedded", repo: "", tag: "", digest: "0f".repeat(32), name: "", commit: "" },
        cryptoMaterial: [
          { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) },
          { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: "11".repeat(32) },
        ],
        freshnessExpiresAt: new Date("2026-10-03T07:00:00-05:00"),
      }),
      { verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, verifiedAt: GOLDEN_AT },
    );
    expectGolden("acceptance-config-facts", report);
    expect(report.verifiedFacts!.toJSON()).toStrictEqual(report.toJSON().verified_facts);
  });

  // TestReportJSONGoldenProvenanceRejectionWithoutKeys in tinfoil-go's verify/report_json_test.go.
  it('keeps "measured": {} for a document that endorses no keys: rejection-provenance-no-keys', async () => {
    const nonce = new Uint8Array(NONCE_SIZE);
    const { bytes } = await buildDocument({ nonce, collateralFormat: FORMAT_V3 }, () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: utf8("quote") }));
    const v = await Verifier.create();
    const report = rejectionReport(await v.verifyV3At(bytes, nonce, { project: "org/project" }, GOLDEN_AT).catch((e: unknown) => e));
    expect(report.partialFacts!.measured).toEqual({});
    expectGolden("rejection-provenance-no-keys", report);
  });

  // TestReportJSONGoldenQuoteRejectionAfterSkippedProvenance in tinfoil-go's
  // verify/report_json_test.go, with embeddedInputs and embeddedDocument
  // from its verify/embedded_test.go. The runtime and platform bytes are the
  // ones that Go marshals, so that their digests match.
  it("skips provenance with its reason when the verifier embeds every reference value: rejection-quote-skipped-provenance", async () => {
    const zero = "00".repeat(48);
    const runtime = utf8(
      JSON.stringify({
        version: "v0.15.0",
        igvm: { format_version: 1, snp_launch: { measurement: "ab".repeat(48) }, tdx_launch: { mrtd: "cd".repeat(48), rtmr0: zero, rtmr1: zero, rtmr2: zero, rtmr3: zero } },
      }),
    );
    const platform = utf8(JSON.stringify({ format: ARTIFACT_FORMAT_V2, machines: {}, policies: {} }));
    const config = utf8(`{"cvm-version":"0.15.0@sha256:${toHex(await sha256(runtime))}"}`);
    const v = await Verifier.create({ kind: "embeddedConfig", name: "/org/project/v1", bytes: config }, { artifacts: { kind: "embeddedArtifacts", runtime, platform } });
    const nonce = new Uint8Array(NONCE_SIZE);
    const { bytes } = await buildDocument({ nonce, collateralFormat: FORMAT_V3 }, () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: utf8("unauthenticated quote") }));
    const report = rejectionReport(await v.verifyV3At(bytes, nonce, {}, GOLDEN_AT).catch((e: unknown) => e));
    expectGolden("rejection-quote-skipped-provenance", report);
  });
});

const vectorGoldens = [...goldens].filter(([, g]) => g.vector !== undefined);

describe.skipIf(!conformanceAvailable())(vectorsTitle("the report's JSON form of a full-verify vector, against the golden files"), () => {
  it("covers the seven golden files that name a vector", () => {
    expect(vectorGoldens).toHaveLength(7);
  });

  // The conformance adapter writes the report in the JSON form, so this
  // checks the adapter's output as well as the verifier's report.
  it.for(vectorGoldens)("%s", async ([name, g]) => {
    // A golden file names its vector under the suite's vectors/ directory, and the loader reads vectors/v3.
    const fixture = loadFixture(`../${g.vector!}`);
    expect(fixture.stage).toBe(Stage.Verify);
    const { output } = await run(fixture.stage, fixture.input);
    expect(output.accepted).toBe(fixture.expected.accepted);
    expectGolden(name, output.report);
  });
});

describe("the report's host", () => {
  const passedReport = (): VerificationReport => {
    const b = new ReportBuilder();
    for (const layer of ["envelope", "provenance", "quote", "policy"] as const) b.passed(layer);
    const launch = new Uint8Array(48);
    return b.passedAll(
      verifiedFactsOf({
        configRepo: "tinfoilsh/repo",
        codeDigest: "0a".repeat(32),
        codeTag: "v1",
        codeMeasurement: { platform: "sev-snp", launch },
        enclaveMeasurement: { platform: "sev-snp", launch },
        cryptoMaterial: [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) }],
      }),
      { verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, verifiedAt: GOLDEN_AT },
    );
  };
  const rejectedReport = (): VerificationReport => {
    const b = new ReportBuilder();
    b.passed("envelope");
    return b.failed("provenance", "no release", { verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, verifiedAt: GOLDEN_AT });
  };

  it("is absent from the verifier's reports and from their JSON form", () => {
    for (const report of [passedReport(), rejectedReport()]) {
      expect(report.metadata.host).toBeUndefined();
      expect(report.toJSON().metadata).not.toHaveProperty("host");
    }
  });

  it("is set on a copy by withHost, written as metadata.host, and kept by clone, for an accepted and a rejected report", () => {
    for (const report of [passedReport(), rejectedReport()]) {
      const named = report.withHost("enclave.example:8443");
      expect(named).not.toBe(report);
      expect(Object.isFrozen(named)).toBe(true);
      expect(Object.isFrozen(named.metadata)).toBe(true);
      expect(named.metadata.host).toBe("enclave.example:8443");
      expect(report.metadata.host).toBeUndefined();
      const json = JSON.parse(JSON.stringify(named)) as VerificationReportJSON;
      expect(json.schema_version).toBe(1);
      expect(json.metadata).toStrictEqual({ verified_at: "2026-01-02T02:04:05Z", verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, host: "enclave.example:8443" });
      // Everything but the host is the report's own.
      expect({ ...named.toJSON(), metadata: undefined }).toStrictEqual({ ...report.toJSON(), metadata: undefined });
      expect(named.clone().metadata.host).toBe("enclave.example:8443");
      expect(named.withHost("").toJSON().metadata).not.toHaveProperty("host");
      expect(named.withHost("").metadata).not.toHaveProperty("host");
    }
  });

  it("refuses a host that isn't a string", () => {
    expect(() => passedReport().withHost(7 as unknown as string)).toThrow(UsageError);
  });
});
