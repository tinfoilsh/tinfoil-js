/**
 * The verification report: its steps and facts on success and on each kind
 * of failure, the rules that tie the facts to the steps that establish
 * them, and the report as plain, immutable data.
 */
import { describe, expect, it } from "vitest";
import { dangerousTestOnlyVerifier } from "../conformance/testing.js";
import { CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_ID, FORMAT_V3, ROLE_REFERENCE_VALUES } from "../src/document/collateral/collateral.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { UsageError, VerificationError } from "../src/errors.js";
import { sha256, toHex } from "../src/internal/bytes.js";
import { ARTIFACT_FORMAT_V2 } from "../src/internal/policy/artifact.js";
import type { ExpectedSevSnp, ExpectedTdx, SevSnpMeasurement, TdxMeasurement } from "../src/measurement.js";
import { hpkePublicKeyFP, ReportBuilder, type StepStatus, type VerificationReport } from "../src/report.js";
import { verifiedFactsOf } from "../src/verification.js";
import { Verifier, type ConfigTrust } from "../src/verifier.js";
import { buildDocument } from "./helpers/builder.js";
import { conformanceAvailable, inputBytes, loadFixture, repoOf, vectorsTitle } from "./helpers/conformance.js";
import { clockOf, rootsOf } from "./helpers/verify.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));
const reg = (fill: number): Uint8Array => new Uint8Array(48).fill(fill);
const METADATA = { verifier: { name: "n", version: "v" }, verifiedAt: new Date("2026-01-02T03:04:05Z") };

const statuses = (r: VerificationReport): StepStatus[] => r.steps.map((s) => s.status);

/** The report of a rejection, checked against the error that carries it. */
function rejectedReport(err: unknown, layer: string): VerificationReport {
  expect(err).toBeInstanceOf(VerificationError);
  const rejected = err as VerificationError;
  expect(rejected.layer).toBe(layer);
  const report = rejected.report;
  expect(report.verifiedFacts).toBeUndefined();
  expect(report.partialFacts).toBeDefined();
  // The step's message is the failing check's, without the error's `verification error: <layer>: ` prefix.
  expect(report.failedStep()).toEqual({ layer, status: "failed", message: rejected.message.slice(`verification error: ${layer}: `.length) });
  expect(report.failedStep()?.message).not.toMatch(/^verification error:/);
  expect(report.steps.map((s) => s.layer)).toEqual(["envelope", "provenance", "quote", "policy"]);
  return report;
}

describe("VerificationReport", () => {
  const facts = () =>
    verifiedFactsOf({
      codeDigest: "d",
      codeTag: "v1",
      configRepo: "org/repo",
      codeMeasurement: { platform: "sev-snp", launch: reg(1) },
      enclaveMeasurement: { platform: "sev-snp", launch: reg(1) },
      cryptoMaterial: [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "fp" }],
      freshnessExpiresAt: new Date("2026-01-03T00:00:00Z"),
    });
  const passed = (): VerificationReport => {
    const b = new ReportBuilder();
    for (const layer of ["envelope", "provenance", "quote", "policy"]) b.passed(layer);
    return b.passedAll(facts(), METADATA);
  };
  const failed = (): VerificationReport => {
    const b = new ReportBuilder();
    b.passed("envelope");
    b.passed("provenance");
    b.passed("quote");
    b.measured = { tlsPublicKeyFP: "fp", cpu: { measurement: { platform: "tdx", mrtd: reg(1), rtmr0: reg(2), rtmr1: reg(3), rtmr2: reg(4), rtmr3: reg(5) } } };
    b.expected = {
      configRepo: "org/repo",
      artifact: { source: "endorsement", repo: "org/repo", tag: "v1", digest: "d", name: "n", commit: "c", approvalTime: new Date("2026-01-01T00:00:00Z") },
      codeMeasurement: { platform: "tdx", rtmr1: reg(9) },
      measurement: { platform: "tdx", mrtd: reg(1), rtmr0: reg(2), rtmr1: reg(9), rtmr2: reg(4), rtmr3: reg(5) },
    };
    return b.failed("policy", "RTMR1 mismatch", METADATA);
  };

  it("starts every step as not run, and holds exactly one kind of facts", () => {
    const b = new ReportBuilder();
    const r = b.failed("envelope", "bad", METADATA);
    expect(statuses(r)).toEqual(["failed", "not_run", "not_run", "not_run"]);
    expect(r.partialFacts).toEqual({});
    expect(r.verifiedFacts).toBeUndefined();
    expect(passed().partialFacts).toBeUndefined();
    expect(passed().failedStep()).toBeUndefined();
    expect(failed().failedStep()).toEqual({ layer: "policy", status: "failed", message: "RTMR1 mismatch" });
  });

  it("is frozen with everything nested in it, and copies what it was built from", () => {
    const r = failed();
    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(r.steps)).toBe(true);
    expect(Object.isFrozen(r.steps[0])).toBe(true);
    expect(Object.isFrozen(r.partialFacts)).toBe(true);
    expect(Object.isFrozen(r.partialFacts!.expected)).toBe(true);
    expect(Object.isFrozen(r.partialFacts!.expected!.artifact)).toBe(true);
    expect(Object.isFrozen(r.partialFacts!.measured!.cpu)).toBe(true);
    expect(Object.isFrozen(r.metadata)).toBe(true);
    expect(() => {
      (r.steps[0] as { status: string }).status = "passed";
    }).toThrow(TypeError);
    expect(() => {
      (r.partialFacts!.measured as { tlsPublicKeyFP: string }).tlsPublicKeyFP = "other";
    }).toThrow(TypeError);
  });

  it("clones into a report that shares no register bytes or dates", () => {
    for (const r of [passed(), failed()]) {
      const copy = r.clone();
      expect(copy).toBeInstanceOf(Object.getPrototypeOf(r).constructor);
      expect(copy.toJSON()).toStrictEqual(r.toJSON());
      copy.metadata.verifiedAt.setFullYear(1999);
      const launch = (copy.verifiedFacts?.enclaveMeasurement as SevSnpMeasurement | undefined)?.launch;
      launch?.fill(0xff);
      (copy.partialFacts?.measured?.cpu?.measurement as TdxMeasurement | undefined)?.mrtd.fill(0xff);
      (copy.partialFacts?.expected?.codeMeasurement as ExpectedTdx | undefined)?.rtmr1?.fill(0xff);
      expect(copy.toJSON()).not.toStrictEqual(r.toJSON());
      expect(r.metadata.verifiedAt.getUTCFullYear()).toBe(2026);
    }
    expect((passed().verifiedFacts!.enclaveMeasurement as SevSnpMeasurement).launch).toEqual(reg(1));
  });

  it("serializes to plain JSON with hex registers and ISO times", () => {
    const json = failed().toJSON();
    expect(json).toStrictEqual({
      steps: [
        { layer: "envelope", status: "passed", message: "" },
        { layer: "provenance", status: "passed", message: "" },
        { layer: "quote", status: "passed", message: "" },
        { layer: "policy", status: "failed", message: "RTMR1 mismatch" },
      ],
      partialFacts: {
        expected: {
          configRepo: "org/repo",
          artifact: { source: "endorsement", repo: "org/repo", tag: "v1", digest: "d", name: "n", commit: "c", approvalTime: "2026-01-01T00:00:00.000Z" },
          codeMeasurement: { platform: "tdx", rtmr1: "09".repeat(48) },
          measurement: { platform: "tdx", mrtd: "01".repeat(48), rtmr0: "02".repeat(48), rtmr1: "09".repeat(48), rtmr2: "04".repeat(48), rtmr3: "05".repeat(48) },
        },
        measured: {
          cpu: { measurement: { platform: "tdx", mrtd: "01".repeat(48), rtmr0: "02".repeat(48), rtmr1: "03".repeat(48), rtmr2: "04".repeat(48), rtmr3: "05".repeat(48) } },
          tlsPublicKeyFP: "fp",
        },
      },
      metadata: { verifier: { name: "n", version: "v" }, verifiedAt: "2026-01-02T03:04:05.000Z" },
    });
    expect(JSON.parse(JSON.stringify(failed()))).toStrictEqual(json);
    expect(passed().toJSON().verifiedFacts).toStrictEqual(passed().verifiedFacts!.toJSON());
  });

  it("survives a structured clone, as postMessage sends it", () => {
    for (const r of [passed(), failed()]) {
      const sent = structuredClone(r) as unknown as Record<string, unknown>;
      expect(Object.keys(sent)).toEqual(Object.keys(r));
      expect(sent.steps).toEqual(r.steps);
      expect(sent.metadata).toEqual(r.metadata);
      expect(sent.partialFacts).toEqual(r.partialFacts);
      expect((sent.verifiedFacts as Record<string, unknown> | undefined)?.codeDigest).toBe(r.verifiedFacts?.codeDigest);
    }
  });

  it("fingerprints an HPKE key as the SHA-256 of its bytes, and refuses anything but lowercase hex", async () => {
    const key = "ab".repeat(32);
    expect(await hpkePublicKeyFP(key)).toBe(toHex(await sha256(hex(key))));
    expect(await hpkePublicKeyFP(key)).toMatch(/^[0-9a-f]{64}$/);
    for (const bad of ["", "AB".repeat(32), "abc", "zz"]) expect(await hpkePublicKeyFP(bad)).toBeUndefined();
  });
});

describe("the report of a config-based verification", () => {
  const register = "cd".repeat(48);
  const manifest = utf8(
    JSON.stringify({
      version: "v1.2.3",
      igvm: { format_version: 1, snp_launch: { measurement: register }, tdx_launch: { mrtd: register, rtmr0: "0".repeat(96), rtmr1: "0".repeat(96), rtmr2: "0".repeat(96), rtmr3: "0".repeat(96) } },
    }),
  );
  const platform = utf8(JSON.stringify({ format: ARTIFACT_FORMAT_V2, measurements: {}, machines: {}, policies: {} }));
  const embeddedArtifacts = { artifacts: { kind: "embeddedArtifacts" as const, runtime: manifest, platform } };
  const nonce = new Uint8Array(NONCE_SIZE).fill(7);
  const hpke = "ef".repeat(32);
  const tls = "12".repeat(32);

  /** A document with config collateral, channel keys and a quote that never authenticates. */
  async function document(): Promise<Uint8Array> {
    const config = utf8(`name: app\ncvm-version: v1.2.3@sha256:${toHex(await sha256(manifest))}\n`);
    const data = JSON.stringify({ endorsement_ref: `sha256:${"ab".repeat(32)}`, config_base64: Buffer.from(config).toString("base64"), sigstore_bundle: {} });
    const { bytes } = await buildDocument(
      {
        nonce,
        collateralFormat: FORMAT_V3,
        cryptoMaterial: [
          { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: tls },
          { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: hpke },
        ],
        collateral: [{ id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_ENDORSEMENT_V2_FORMAT, data }],
      },
      () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: new Uint8Array(1184).fill(1) }),
    );
    return bytes;
  }

  const verify = async (config: ConfigTrust): Promise<unknown> => {
    const v = await Verifier.create(config, embeddedArtifacts);
    return v.verifyV3At(await document(), nonce, {}, new Date()).catch((e: unknown) => e);
  };

  it("skips provenance only when the verifier embeds the config, the runtime and the platform", async () => {
    const runtime = { repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: toHex(await sha256(manifest)) };
    const report = rejectedReport(await verify({ kind: "embeddedConfigReference", digest: "aa".repeat(32), runtime }), "quote");
    expect(statuses(report)).toEqual(["passed", "skipped", "failed", "not_run"]);
    expect(report.steps[1]!.message).not.toBe("");
    const expected = report.partialFacts!.expected!;
    expect(expected.config?.source).toBe("embedded");
    expect(expected.artifact.source).toBe("embedded");
    expect(expected.platform?.source).toBe("embedded");
    expect(expected.configRepo).toBe("tinfoilsh/cvmimage");
    // The code measurement is laid out for the platform that the evidence names, before the quote authenticates.
    expect(expected.codeMeasurement).toEqual({ platform: "sev-snp", launch: hex(register) });
    expect(expected.measurement).toBeUndefined();
    // No CPU measurement for a quote that failed to authenticate; the keys are the document's claim.
    expect(report.partialFacts!.measured).toEqual({ tlsPublicKeyFP: tls, hpkePublicKeyFP: await hpkePublicKeyFP(hpke) });
  });

  it("reports provenance as passed when a config authorizer accepted the config", async () => {
    const report = rejectedReport(await verify({ kind: "configAuthorizer", authorize: () => undefined }), "quote");
    expect(statuses(report)).toEqual(["passed", "passed", "failed", "not_run"]);
    expect(report.partialFacts!.expected!.config?.source).toBe("policy");
    expect((report.partialFacts!.expected!.codeMeasurement as ExpectedSevSnp).launch).toEqual(hex(register));
  });

  it("fails provenance with the authorizer's error as the cause, and no expected facts", async () => {
    const refusal = new Error("not this config");
    const err = await verify({
      kind: "configAuthorizer",
      authorize: () => {
        throw refusal;
      },
    });
    const report = rejectedReport(err, "provenance");
    expect((err as VerificationError).cause).toBe(refusal);
    expect((err as VerificationError).message).toBe("verification error: provenance: authorizing config: not this config");
    expect(report.failedStep()?.message).toBe("authorizing config: not this config");
    expect(statuses(report)).toEqual(["passed", "failed", "not_run", "not_run"]);
    expect(report.partialFacts!.expected).toBeUndefined();
    expect(report.partialFacts!.measured?.tlsPublicKeyFP).toBe(tls);
  });

  it("fails the envelope with no facts at all, and reports a usage error with no report", async () => {
    const v = await Verifier.create({ kind: "configAuthorizer", authorize: () => undefined }, embeddedArtifacts);
    const other = new Uint8Array(NONCE_SIZE).fill(8);
    const report = rejectedReport(await v.verifyV3At(await document(), other, {}, new Date()).catch((e: unknown) => e), "envelope");
    expect(statuses(report)).toEqual(["failed", "not_run", "not_run", "not_run"]);
    expect(report.partialFacts).toEqual({});
    const usage = await v.verifyV3At(await document(), nonce.subarray(1), {}, new Date()).catch((e: unknown) => e);
    expect(usage).toBeInstanceOf(UsageError);
    expect("report" in (usage as object)).toBe(false);
  });
});

describe.skipIf(!conformanceAvailable())(vectorsTitle("the report of a full-verify vector"), () => {
  async function verifyVector(path: string): Promise<{ report?: VerificationReport; err?: unknown }> {
    const fixture = loadFixture(path);
    const verifier = await dangerousTestOnlyVerifier(rootsOf(fixture));
    return verifier.verifyV3At(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""), { repo: repoOf(fixture) }, clockOf(fixture)).then(
      (report) => ({ report }),
      (err: unknown) => ({ err }),
    );
  }

  it("passes every step of an accepted document, with verified facts only", async () => {
    const { report } = await verifyVector("golden/golden-happy.json");
    expect(statuses(report!)).toEqual(["passed", "passed", "passed", "passed"]);
    expect(report!.partialFacts).toBeUndefined();
    expect(report!.verifiedFacts?.hpkePublicKey).toBeDefined();
  });

  it("fails the envelope of a stale nonce with no facts", async () => {
    const report = rejectedReport((await verifyVector("freshness/fr1-nonce-stale.json")).err, "envelope");
    expect(statuses(report)).toEqual(["failed", "not_run", "not_run", "not_run"]);
    expect(report.partialFacts).toEqual({});
  });

  it("fails provenance of a stale witness with the document's key fingerprints, unverified", async () => {
    const report = rejectedReport((await verifyVector("freshness/fr2-stale.json")).err, "provenance");
    expect(statuses(report)).toEqual(["passed", "failed", "not_run", "not_run"]);
    expect(report.partialFacts!.expected).toBeUndefined();
    const measured = report.partialFacts!.measured!;
    expect(measured.cpu).toBeUndefined();
    expect(measured.tlsPublicKeyFP).toMatch(/^[0-9a-f]{64}$/);
    expect(measured.hpkePublicKeyFP).toMatch(/^[0-9a-f]{64}$/);
  });

  it("shows both sides of a launch measurement mismatch", async () => {
    const report = rejectedReport((await verifyVector("golden/s14-measurement.json")).err, "policy");
    expect(statuses(report)).toEqual(["passed", "passed", "passed", "failed"]);
    const expected = report.partialFacts!.expected!;
    expect(expected.artifact.digest).not.toBe("");
    expect(expected.configRepo).toBe(expected.artifact.repo);
    const code = expected.codeMeasurement as ExpectedSevSnp;
    const full = expected.measurement as SevSnpMeasurement;
    expect(full.platform).toBe("sev-snp");
    expect(full.launch).toEqual(code.launch);
    expect(report.partialFacts!.measured!.cpu!.measurement).not.toEqual(full);
  });

  it("adds the endorsed platform registers to the full TDX expectation, once they resolve", async () => {
    let report = rejectedReport((await verifyVector("golden-tdx/t18-rtmr1.json")).err, "policy");
    const expected = report.partialFacts!.expected!;
    const code = expected.codeMeasurement as ExpectedTdx;
    expect(code.mrtd).toBeUndefined();
    const full = expected.measurement as TdxMeasurement;
    const cpu = report.partialFacts!.measured!.cpu!.measurement as TdxMeasurement;
    expect(full.mrtd).toEqual(cpu.mrtd);
    expect(full.rtmr0).toEqual(cpu.rtmr0);
    expect(full.rtmr1).toEqual(code.rtmr1);
    expect(full.rtmr1).not.toEqual(cpu.rtmr1);

    // A platform register that no endorsement resolves fails the policy step before the expectation is complete.
    report = rejectedReport((await verifyVector("golden-tdx/t17-rtmr0.json")).err, "policy");
    expect(report.partialFacts!.expected!.measurement).toBeUndefined();
    expect(report.partialFacts!.expected!.codeMeasurement).toBeDefined();
    expect(report.partialFacts!.measured!.cpu).toBeDefined();
  });
});
