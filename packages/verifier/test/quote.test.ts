/**
 * Policy assembly: the shared resolution steps (pins, completeness, policy
 * lookup), the two reference-value contracts (a code release, a
 * config-pinned runtime) and the assemble/validate dispatch, driven by the
 * golden SEV-SNP and TDX documents and their endorsed policy artifacts.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { parse as parseDocument, type Document } from "../src/document/document.js";
import { sha256 } from "../src/internal/bytes.js";
import { decodeManifest } from "../src/internal/runtime/manifest.js";
import { parse as parseArtifact, type Artifact } from "../src/internal/policy/artifact.js";
import type { Shape } from "../src/internal/policy/shape.js";
import { resolveConfig } from "../src/internal/quote/config.js";
import { resolveLegacy } from "../src/internal/quote/legacy.js";
import { applyPins, assemble, assembleWith, authenticate, complete, resolvePolicy, validate, type Authenticated } from "../src/internal/quote/quote.js";
import { parseExpectedSevSnp, parseExpectedTdx, parseRegister, registerHex, type Expected } from "../src/measurement.js";
import { conformanceAvailable, decodeDocument, inputBytes, loadFixture, vectorsTitle, type ConformanceFixture } from "./helpers/conformance.js";
import { clockOf, rootsOf } from "./helpers/verify.js";

const withoutVectors = !conformanceAvailable();
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));
const reg = (fill: number) => new Uint8Array(48).fill(fill);

/** The platform-endorsements artifact and code predicate a golden document carries, as the bundles state them. */
function predicates(fixture: ConformanceFixture): { artifactJson: Record<string, any>; code: Record<string, any> } {
  const doc = decodeDocument(fixture);
  const payload = (pattern: RegExp): Record<string, any> => {
    const entry = doc.collateral.find((c) => pattern.test(c.format));
    if (entry === undefined) throw new Error(`no ${pattern} collateral`);
    return JSON.parse(Buffer.from(entry.data.sigstore_bundle.dsseEnvelope.payload, "base64").toString("utf8")).predicate;
  };
  return { artifactJson: payload(/sigstore-platform/), code: payload(/sigstore-code/) };
}

const artifactOf = (json: Record<string, any>): Artifact => parseArtifact(utf8(JSON.stringify(json)));

function shapeOf(code: Record<string, any>): Shape {
  const s = code.vm_shape;
  return { cpus: BigInt(s.cpus), memoryMb: BigInt(s.memory_mb), gpus: s.gpus === undefined ? undefined : BigInt(s.gpus), disks: BigInt(s.disks) };
}

interface Material {
  readonly doc: Document;
  readonly q: Authenticated;
  readonly artifact: Artifact;
  readonly artifactJson: Record<string, any>;
  readonly code: Record<string, any>;
}

async function materialOf(path: string): Promise<Material> {
  const fixture = loadFixture(path);
  const doc = await parseDocument(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""));
  const q = await authenticate(doc.cpuEvidence(), doc.cpuEndorsements(), clockOf(fixture), { dangerousTestOnlyRoots: rootsOf(fixture) });
  const { artifactJson, code } = predicates(fixture);
  return { doc, q, artifact: artifactOf(artifactJson), artifactJson, code };
}

describe("applyPins", () => {
  const code: Expected = { platform: "tdx", rtmr1: reg(1), rtmr2: reg(2) };

  it("returns the code registers untouched without pins", () => {
    expect(applyPins(code, "tdx", undefined)).toBe(code);
  });

  it("fills open registers and keeps fixed ones", () => {
    const merged = applyPins(code, "tdx", { platform: "tdx", mrtd: reg(5), rtmr1: reg(1) });
    expect(merged).toEqual({ platform: "tdx", mrtd: reg(5), rtmr0: undefined, rtmr1: reg(1), rtmr2: reg(2), rtmr3: undefined });
    expect(applyPins({ platform: "sev-snp" }, "sev-snp", { platform: "sev-snp", launch: reg(3) })).toEqual({ platform: "sev-snp", launch: reg(3) });
  });

  it("rejects a pin that disagrees with a fixed register", () => {
    expect(() => applyPins(code, "tdx", { platform: "tdx", rtmr2: reg(9) })).toThrow(/pinned RTMR2 does not match the signed release measurement/);
    expect(() => applyPins({ platform: "sev-snp", launch: reg(1) }, "sev-snp", { platform: "sev-snp", launch: reg(2) })).toThrow(
      /pinned launch measurement does not match/,
    );
  });

  it("rejects pins for the other platform", () => {
    expect(() => applyPins(code, "tdx", { platform: "sev-snp", launch: reg(1) })).toThrow(/pinned registers are for sev-snp, but the enclave is tdx/);
    expect(() => applyPins({ platform: "sev-snp" }, "sev-snp", { platform: "tdx" })).toThrow(/pinned registers are for tdx, but the enclave is sev-snp/);
  });
});

describe("complete", () => {
  it("turns a fully fixed expectation into a measurement", () => {
    expect(complete({ platform: "sev-snp", launch: reg(1) })).toEqual({ platform: "sev-snp", launch: reg(1) });
    const tdx = parseExpectedTdx(registerHex(reg(1)), registerHex(reg(2)), registerHex(reg(3)), registerHex(reg(4)), registerHex(reg(5)));
    expect(complete(tdx)).toEqual({ platform: "tdx", mrtd: reg(1), rtmr0: reg(2), rtmr1: reg(3), rtmr2: reg(4), rtmr3: reg(5) });
  });

  it("names every register nothing fixes", () => {
    expect(() => complete({ platform: "sev-snp" })).toThrow(/nothing fixes the expected launch measurement/);
    expect(() => complete({ platform: "tdx", rtmr1: reg(1) })).toThrow(/nothing fixes the expected MRTD, RTMR0, RTMR2, RTMR3/);
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("assembly for an SEV-SNP code release"), () => {
  let m: Material;
  beforeAll(async () => {
    m = await materialOf("golden/golden-happy.json");
  });

  const legacy = (artifact: Artifact = m.artifact) => ({
    kind: "legacy" as const,
    endorsements: artifact,
    sevSnp: parseExpectedSevSnp(m.code.snp_measurement),
    tdx: parseExpectedTdx("", "", m.code.tdx_measurement.rtmr1, m.code.tdx_measurement.rtmr2, ""),
    shape: shapeOf(m.code),
  });

  it("looks up the machine's policy by identity and platform", () => {
    expect(resolvePolicy(m.artifact, m.q).policyName).toBe("sev-policy");
    expect(() => resolvePolicy(m.artifact, { ...m.q, identity: "ab".repeat(64) })).toThrow(/is not endorsed/);
    expect(() => resolvePolicy(m.artifact, { ...m.q, platform: "tdx" })).toThrow(/is for platform "sev-snp", evidence is "tdx"/);
  });

  it("resolves the release launch measurement and the policy's host data", () => {
    const r = resolveLegacy(legacy(), m.q, undefined);
    expect(r.policyName).toBe("sev-policy");
    expect(r.platformMeasurementName).toBe("");
    expect(r.code).toEqual({ platform: "sev-snp", launch: parseRegister(m.code.snp_measurement) });
    expect(r.expected).toEqual(r.code);
    expect(r.hostData).toEqual(hex(m.artifactJson.policies["sev-policy"].sev_snp.host_data));
  });

  it("assembles against the document's bound REPORT_DATA and validates the quote", async () => {
    const p = await assemble(m.doc, legacy(), undefined, m.q);
    expect(p.policyName).toBe("sev-policy");
    expect(p.codeMeasurement).toEqual({ platform: "sev-snp", launch: parseRegister(m.code.snp_measurement) });
    expect(p.sev).toBeDefined();
    expect(p.tdx).toBeUndefined();
    await expect(validate(p)).resolves.toBeUndefined();
  });

  it("refuses a document that was not bound to a nonce, or another document's quote", async () => {
    const unbound = await import("../src/document/document.js").then((d) => d.dangerousTestOnlyDecode(inputBytes(loadFixture("golden/golden-happy.json"), "document_b64")));
    await expect(assemble(unbound, legacy(), undefined, m.q)).rejects.toThrow(/a document checked by document.parse is required/);
    const other: Authenticated = { ...m.q, evidence: { ...m.q.evidence, report: m.q.evidence.report.map((b) => b ^ 1) } };
    await expect(assemble(m.doc, legacy(), undefined, other)).rejects.toThrow(/not this document's CPU evidence/);
  });

  it("rejects a release whose measurement the quote does not carry", async () => {
    const refs = { ...legacy(), sevSnp: { platform: "sev-snp" as const, launch: reg(9) } };
    await expect(validate(await assemble(m.doc, refs, undefined, m.q))).rejects.toThrow(/MEASUREMENT does not match/);
  });

  it("leaves nothing unfixed: a release without a launch measurement rejects", async () => {
    await expect(assemble(m.doc, { ...legacy(), sevSnp: { platform: "sev-snp" } }, undefined, m.q)).rejects.toThrow(/nothing fixes the expected launch measurement/);
  });

  it("resolves a config-pinned runtime: the manifest's launch measurement and the config hash as host data", async () => {
    const policy = m.artifactJson.policies["sev-policy"];
    const v2 = artifactOf({
      ...m.artifactJson,
      format: "https://tinfoil.sh/predicate/platform-endorsements/v2",
      measurements: {},
      policies: { "sev-policy": { ...policy, sev_snp: { ...policy.sev_snp, host_data: "" } } },
    });
    const hash = hex(policy.sev_snp.host_data);
    const runtime = { formatVersion: 1n, snpLaunch: { measurement: m.code.snp_measurement }, tdxLaunch: { mrtd: "", rtmr0: "", rtmr1: "", rtmr2: "", rtmr3: "" } };
    const refs = { kind: "config" as const, endorsements: v2, runtime, hash };
    const r = resolveConfig(refs, m.q, undefined);
    expect(r.code).toEqual({ platform: "sev-snp", launch: parseRegister(m.code.snp_measurement) });
    expect(r.hostData).toEqual(hash);
    const p = await assemble(m.doc, refs, undefined, m.q);
    await expect(validate(p)).resolves.toBeUndefined();
    await expect(validate(await assemble(m.doc, { ...refs, hash: new Uint8Array(32).fill(1) }, undefined, m.q))).rejects.toThrow(/HOST_DATA does not match/);
  });

  it("refuses a config runtime against a policy that declares host data, and incomplete runtime endorsements", () => {
    const runtime = { formatVersion: 1n, snpLaunch: { measurement: m.code.snp_measurement }, tdxLaunch: { mrtd: "", rtmr0: "", rtmr1: "", rtmr2: "", rtmr3: "" } };
    expect(() => resolveConfig({ kind: "config", endorsements: m.artifact, runtime, hash: new Uint8Array(32) }, m.q, undefined)).toThrow(
      /config runtime cannot be combined with platform host_data/,
    );
    expect(() => resolveConfig({ kind: "config", endorsements: m.artifact, runtime: { formatVersion: 1n }, hash: new Uint8Array(32) }, m.q, undefined)).toThrow(
      /complete runtime endorsements are required/,
    );
    expect(() => resolveConfig({ kind: "config", endorsements: m.artifact, runtime, hash: new Uint8Array(31) }, m.q, undefined)).toThrow(/config hash must be 32 bytes/);
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("assembly for a TDX code release"), () => {
  let m: Material;
  beforeAll(async () => {
    m = await materialOf("golden-tdx/tdx-golden-happy.json");
  });

  const legacy = (shape: Shape | undefined = shapeOf(m.code)) => ({
    kind: "legacy" as const,
    endorsements: m.artifact,
    sevSnp: parseExpectedSevSnp(m.code.snp_measurement),
    tdx: parseExpectedTdx("", "", m.code.tdx_measurement.rtmr1, m.code.tdx_measurement.rtmr2, ""),
    shape,
  });

  it("takes MRTD and RTMR0 from the platform measurement matching the quote and the release's shape, and RTMR3 as zero", () => {
    const r = resolveLegacy(legacy(), m.q, undefined);
    if (m.q.measurement.platform !== "tdx" || r.expected.platform !== "tdx") throw new Error("TDX material expected");
    expect(r.platformMeasurementName).not.toBe("");
    expect(r.expected.mrtd).toEqual(m.q.measurement.mrtd);
    expect(r.expected.rtmr0).toEqual(m.q.measurement.rtmr0);
    expect(r.expected.rtmr1).toEqual(parseRegister(m.code.tdx_measurement.rtmr1));
    expect(r.expected.rtmr3).toEqual(new Uint8Array(48));
    expect(r.code).toEqual(parseExpectedTdx("", "", m.code.tdx_measurement.rtmr1, m.code.tdx_measurement.rtmr2, ""));
    expect(r.configId).toEqual(new Uint8Array(48));
  });

  it("requires a VM shape and a platform measurement that satisfies it", () => {
    expect(() => resolveLegacy({ ...legacy(), shape: undefined }, m.q, undefined)).toThrow(/required VM shape is missing/);
    const huge: Shape = { cpus: 4096n, memoryMb: 1n, disks: 1n };
    expect(() => resolveLegacy(legacy(huge), m.q, undefined)).toThrow(/no endorsed platform measurement matches the required VM shape/);
  });

  it("assembles and validates the TDX quote, and honours a pinned RTMR3", async () => {
    const p = await assemble(m.doc, legacy(), undefined, m.q);
    expect(p.tdx).toBeDefined();
    expect(p.platformMeasurementName).not.toBe("");
    await expect(validate(p)).resolves.toBeUndefined();
    const pinned = await assemble(m.doc, legacy(), { platform: "tdx", rtmr3: reg(7) }, m.q);
    await expect(validate(pinned)).rejects.toThrow(/RTMR\[3\]/);
  });

  it("resolves a config-pinned runtime: all five registers from the manifest and MRCONFIGID from the config hash", async () => {
    const policy = m.artifactJson.policies[Object.keys(m.artifactJson.policies)[0]!];
    const name = Object.keys(m.artifactJson.policies)[0]!;
    const v2 = artifactOf({
      ...m.artifactJson,
      format: "https://tinfoil.sh/predicate/platform-endorsements/v2",
      measurements: {},
      policies: { [name]: { ...policy, tdx: { ...policy.tdx, platform_measurements: undefined } } },
    });
    if (m.q.measurement.platform !== "tdx") throw new Error("TDX material expected");
    // The runtime comes from a manifest parsed on its own and the hash from
    // config bytes of its own, so neither can be read off the quote.
    const zero = "00".repeat(48);
    const manifest = decodeManifest(
      utf8(
        JSON.stringify({
          version: "v1.2.3",
          igvm: { format_version: 1, snp_launch: { measurement: "11".repeat(48) }, tdx_launch: { mrtd: "ab".repeat(48), rtmr0: zero, rtmr1: zero, rtmr2: zero, rtmr3: zero } },
        }),
      ),
    );
    const hash = await sha256(utf8("name: app\n"));
    const refs = { kind: "config" as const, endorsements: v2, runtime: manifest.measurements!, hash };
    const r = resolveConfig(refs, m.q, undefined);
    expect(r.code).toEqual({ platform: "tdx", mrtd: reg(0xab), rtmr0: reg(0), rtmr1: reg(0), rtmr2: reg(0), rtmr3: reg(0) });
    expect(r.expected).toEqual(r.code);
    expect(r.configId.subarray(0, 32)).toEqual(hash);
    expect(r.configId.subarray(32)).toEqual(new Uint8Array(16));
    expect(r.hostData).toEqual(new Uint8Array(32));
    expect(() => resolveConfig({ ...refs, endorsements: m.artifact }, m.q, undefined)).toThrow(/cannot be combined with platform_measurements/);
    const p = await assembleWith(refs, undefined, m.q.tdx!.quote.body.reportData, m.q);
    expect(p.tdx?.mrConfigId).toEqual(r.configId);
    expect(p.codeMeasurement).toEqual(r.code);
    // The golden quote measured a different runtime and config, so the
    // assembled expectations reject it.
    await expect(validate(p)).rejects.toThrow(/MR_TD|MR_CONFIG_ID/);
  });
});
