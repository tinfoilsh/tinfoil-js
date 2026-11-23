/**
 * The verification pipeline on the shared full-verify vectors (golden,
 * golden-tdx, freshness, real-frozen): every accept must yield the vector's
 * facts, every rejection must name the vector's layer, and caller mistakes
 * must surface as usage errors rather than rejections.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { expectedOf, measurementOf } from "../conformance/adapter.js";
import { dangerousTestOnlyVerifier } from "../conformance/testing.js";
import { CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_ID, FORMAT_V2, FORMAT_V3, ROLE_REFERENCE_VALUES, SIGSTORE_CODE_V1_FORMAT } from "../src/document/collateral/collateral.js";
import type { ConfigEndorsement } from "../src/document/collateral/config.js";
import type { RuntimeReference } from "../src/document/collateral/runtime.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { UsageError, VerificationError, type Layer } from "../src/errors.js";
import { sha256, toHex } from "../src/internal/bytes.js";
import { CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2, IN_TOTO_STATEMENT_V1, PUBLIC_REGISTRY_ID, REGISTRY_ID_PREFIX } from "../src/internal/endorsement/approval.js";
import { ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2 } from "../src/internal/policy/artifact.js";
import { endorsementReference, timestampInput } from "../src/internal/sigstore/timestamp.js";
import type { Expected } from "../src/measurement.js";
import { PUBLIC_REGISTRY_ID as PUBLIC_REGISTRY_ID_EXPORTED } from "../src/index.js";
import { Verifier, type ArtifactTrust, type ConfigTrust, type EmbeddedConfigReference, type Pin, type Policy } from "../src/verifier.js";
import { VERIFIER_NAME, VERIFIER_VERSION } from "../src/version.js";
import { buildDocument } from "./helpers/builder.js";
import { conformanceAvailable, inputBytes, loadFixture, loadFixtures, repoOf, vectorsTitle, type ConformanceFixture } from "./helpers/conformance.js";
import { b64, build, newLog, newSigner, rootJson, toJson } from "./helpers/keyed.js";
import { newRegistry, registryCertificate } from "./helpers/registry.js";
import { authorityJson, newTimestampAuthority, timestampResponse } from "./helpers/tsa.js";
import { clockOf, rootsOf } from "./helpers/verify.js";

const withoutVectors = !conformanceAvailable();
const FULL_VERIFY_DIRS = ["golden", "golden-tdx", "freshness", "real-frozen"];
const fixtures = withoutVectors ? [] : FULL_VERIFY_DIRS.flatMap((d) => loadFixtures(d));

const LAYER_OF: Record<string, Layer> = {
  ENVELOPE_REJECTED: "envelope",
  PROVENANCE_REJECTED: "provenance",
  QUOTE_REJECTED: "quote",
  POLICY_REJECTED: "policy",
};

const PASSED = ["envelope", "provenance", "quote", "policy"].map((layer) => ({ layer, status: "passed", message: "" }));

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

interface Case {
  readonly fixture: ConformanceFixture;
  readonly doc: Uint8Array;
  readonly nonce: Uint8Array;
  readonly repo: string;
  readonly at: Date;
  readonly verifier: Verifier;
}

async function caseOf(fixture: ConformanceFixture): Promise<Case> {
  return {
    fixture,
    doc: inputBytes(fixture, "document_b64"),
    nonce: hex(fixture.input.nonce_hex ?? ""),
    repo: repoOf(fixture),
    at: clockOf(fixture),
    verifier: await dangerousTestOnlyVerifier(rootsOf(fixture)),
  };
}

describe.skipIf(withoutVectors)(vectorsTitle("verifyV3At on the full-verify vectors"), () => {
  for (const fixture of fixtures) {
    const { expected } = fixture;
    it(`${fixture.id}: ${expected.accepted ? "accepts" : `rejects at ${LAYER_OF[expected.code ?? ""] ?? expected.code}`}`, async () => {
      const c = await caseOf(fixture);
      const run = c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at);
      if (!expected.accepted) {
        if (expected.code === "MALFORMED_INPUT") {
          await expect(run).rejects.toBeInstanceOf(UsageError);
          return;
        }
        const outcome = await run.then(
          (r) => ({ verified: r.verifiedFacts! }),
          (e: unknown) => ({ err: e }),
        );
        if ("verified" in outcome) {
          // The verifier accepts a document that endorses no usable channel
          // keys; the adapter's full stage, like every real client, then
          // rejects it at the envelope layer.
          expect(expected.code).toBe("ENVELOPE_REJECTED");
          expect(outcome.verified.tlsPublicKeyFP === undefined || outcome.verified.hpkePublicKey === undefined).toBe(true);
          return;
        }
        expect(outcome.err).toBeInstanceOf(VerificationError);
        const rejected = outcome.err as VerificationError;
        expect(rejected.layer).toBe(LAYER_OF[expected.code ?? ""]);
        // The report fails the error's layer, with the error's message, and holds partial facts only.
        expect(rejected.report.failedStep()).toEqual({ layer: rejected.layer, status: "failed", message: rejected.message.slice(`verification error: ${rejected.layer}: `.length) });
        // A failure that the verifier attributed to the layer keeps the failing check's message as the step's.
        if (rejected.cause instanceof Error) expect(rejected.report.failedStep()?.message).toBe(rejected.cause.message);
        expect(rejected.report.steps.map((s) => s.layer)).toEqual(["envelope", "provenance", "quote", "policy"]);
        expect(rejected.report.verifiedFacts).toBeUndefined();
        expect(rejected.report.partialFacts).toBeDefined();
        expect(rejected.report.metadata.verifiedAt).toEqual(c.at);
        return;
      }
      const report = await run;
      expect(report.steps).toEqual(PASSED);
      expect(report.partialFacts).toBeUndefined();
      expect(report.failedStep()).toBeUndefined();
      const v = report.verifiedFacts!;
      if (expected.tls_public_key_fp) expect(v.tlsPublicKeyFP).toBe(expected.tls_public_key_fp);
      if (expected.hpke_public_key) expect(v.hpkePublicKey).toBe(expected.hpke_public_key);
      if (expected.code_digest) expect(v.codeDigest).toBe(expected.code_digest);
      if (expected.code_measurement) expect(expectedOf(v.codeMeasurement)).toEqual(expected.code_measurement);
      if (expected.enclave_measurement) expect(measurementOf(v.enclaveMeasurement)).toEqual(expected.enclave_measurement);
      // A code release carries no config, runtime or platform facts, and its
      // witnesses bound the freshness window around the appraisal clock.
      expect(v.configRepo).toBe(c.repo.split("@")[0]);
      expect(v.codeTag).not.toBe("");
      expect(v.config).toBeUndefined();
      expect(v.runtime).toBeUndefined();
      expect(v.platform).toBeUndefined();
      expect(report.metadata.verifiedAt).toEqual(c.at);
      expect(report.metadata.verifier.name).toBe("@tinfoilsh/verifier");
      const expires = v.freshnessExpiresAt;
      expect(expires).toBeDefined();
      expect(expires!.getTime()).toBeGreaterThanOrEqual(c.at.getTime());
      expect(expires!.getTime()).toBeLessThanOrEqual(c.at.getTime() + c.verifier.freshnessMaxAgeMs + 5 * 60 * 1000);
    });
  }
});

describe.skipIf(withoutVectors)(vectorsTitle("hardware expiration"), () => {
  const extendedApprovalAgeMs = 20 * 365 * 24 * 60 * 60 * 1000;
  it.each([
    ["golden/golden-happy.json", "2034-12-30T00:00:00.000Z"],
    ["golden-tdx/tdx-golden-happy.json", "2030-01-01T00:00:00.000Z"],
  ])("caps cached verification at the hardware deadline for %s", async (path, deadline) => {
    const fixture = loadFixture(path);
    const c = await caseOf(fixture);
    const verifier = await dangerousTestOnlyVerifier(rootsOf(fixture), undefined, { freshnessMaxAgeMs: extendedApprovalAgeMs });
    const verified = (await verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at)).verifiedFacts!;
    expect(verified.freshnessExpiresAt).toEqual(new Date(deadline));
    const afterExpiry = new Date(new Date(deadline).getTime() + 1);
    await expect(verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, afterExpiry)).rejects.toMatchObject({ layer: "quote" });
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("the JSON form of a verification report"), () => {
  it("pins the shape of the golden vector's report", async () => {
    const c = await caseOf(loadFixture("golden/golden-happy.json"));
    const v = await c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at);
    const launch = "11".repeat(48);
    const verifiedFacts = {
      codeDigest: "3b29117bcc96bb282879514cc03c32f3f7eb8a7bd031b829dd3864c591b87c50",
      codeTag: "v1.0.0",
      configRepo: "tinfoilsh/confidential-inference-proxy",
      codeMeasurement: { platform: "sev-snp", launch },
      enclaveMeasurement: { platform: "sev-snp", launch },
      cryptoMaterial: [
        { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "d1a3788930750184f2fe268a222b5c65bab974069573c4afbf656454f066b6e3" },
        { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: "58c9b3756d738466ace1e27f83a7fe21b3356ec362694aef1506c5f35c766a01" },
      ],
      freshnessExpiresAt: "2025-01-08T00:00:01.000Z",
    };
    expect(v.verifiedFacts!.toJSON()).toStrictEqual(verifiedFacts);
    const json = {
      steps: PASSED,
      verifiedFacts,
      metadata: { verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, verifiedAt: "2025-01-01T00:00:01.000Z" },
    };
    expect(v.toJSON()).toStrictEqual(json);
    expect(JSON.parse(JSON.stringify(v))).toStrictEqual(json);
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("verifyV3At caller mistakes"), () => {
  let c: Case;
  beforeAll(async () => {
    c = await caseOf(loadFixture("golden/golden-happy.json"));
  });

  it("rejects a nonce of the wrong length as a usage error, not an envelope rejection", async () => {
    await expect(c.verifier.verifyV3At(c.doc, c.nonce.subarray(1), { repo: c.repo }, c.at)).rejects.toThrow(UsageError);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce.subarray(1), { repo: c.repo }, c.at)).rejects.toThrow(/expected nonce must be 32 bytes/);
  });

  it("rejects an invalid verification time", async () => {
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, new Date(NaN))).rejects.toThrow(UsageError);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, "2025-01-01" as unknown as Date)).rejects.toThrow(UsageError);
  });

  it("rejects a malformed repository or project reference as a usage error", async () => {
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, { repo: "not a repo" }, c.at)).rejects.toThrow(UsageError);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo, project: "not a project" }, c.at)).rejects.toThrow(UsageError);
  });

  it("rejects a pin that is not an object of strings as a usage error", async () => {
    // A bare reference from untyped code must not be read as an empty pin.
    for (const bad of [c.repo, null, undefined, { repo: 7 }, { repo: c.repo, project: null }]) {
      await expect(c.verifier.verifyV3At(c.doc, c.nonce, bad as unknown as Pin, c.at)).rejects.toThrow(UsageError);
      expect(() => c.verifier.checkPinVerifiability(bad as unknown as Pin)).toThrow(UsageError);
    }
  });

  it("does not let a project pin stand in for the repository", async () => {
    const err = await c.verifier.verifyV3At(c.doc, c.nonce, { project: c.repo.toLowerCase() }, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/only a registry project is pinned/);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo, project: "org/other" }, c.at)).resolves.toBeDefined();
  });

  it("rejects a different nonce at the envelope layer", async () => {
    const other = new Uint8Array(NONCE_SIZE).fill(7);
    const err = await c.verifier.verifyV3At(c.doc, other, { repo: c.repo }, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("envelope");
  });

  it("rejects another repository at the provenance layer", async () => {
    const err = await c.verifier.verifyV3At(c.doc, c.nonce, { repo: "tinfoilsh/other-repo" }, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
  });

  it("requires config collateral once the policy pins config trust", async () => {
    const verifier = await dangerousTestOnlyVerifier(rootsOf(c.fixture), { kind: "configAuthorizer", authorize: () => undefined });
    const err = await verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/configured trust requires/);
  });

  it("applies pinned registers: a matching pin passes, a conflicting or foreign one rejects at the policy layer", async () => {
    const v = (await c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at)).verifiedFacts!;
    const launch = v.enclaveMeasurement;
    if (launch.platform !== "sev-snp") throw new Error("golden-happy is an SEV-SNP document");
    const matching = await dangerousTestOnlyVerifier(rootsOf(c.fixture), undefined, { pinnedRegisters: { platform: "sev-snp", launch: launch.launch } });
    await expect(matching.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at)).resolves.toBeDefined();
    expect(matching.pinnedRegisters).toEqual({ platform: "sev-snp", launch: launch.launch });
    // The pins are one frozen copy: every read is the same object, and the policy keeps its own.
    expect(matching.pinnedRegisters).toBe(matching.pinnedRegisters);
    expect(Object.isFrozen(matching.pinnedRegisters)).toBe(true);
    (matching.pinnedRegisters as { launch: Uint8Array }).launch[0] ^= 0xff;
    await expect(matching.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at)).resolves.toBeDefined();

    const conflicting = await dangerousTestOnlyVerifier(rootsOf(c.fixture), undefined, { pinnedRegisters: { platform: "sev-snp", launch: new Uint8Array(48).fill(9) } });
    const err = await conflicting.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("policy");
    expect((err as Error).message).toMatch(/pinned launch measurement does not match/);

    const foreign = await dangerousTestOnlyVerifier(rootsOf(c.fixture), undefined, { pinnedRegisters: { platform: "tdx", rtmr3: new Uint8Array(48) } });
    const err2 = await foreign.verifyV3At(c.doc, c.nonce, { repo: c.repo }, c.at).catch((e: unknown) => e);
    expect((err2 as VerificationError).layer).toBe("policy");
    expect((err2 as Error).message).toMatch(/pinned registers are for tdx, but the enclave is sev-snp/);
  });

  it("enforces the freshness window it was built with", async () => {
    // The witnesses were logged at the vector's clock; one second later a
    // one-millisecond window no longer covers them.
    const tight = await dangerousTestOnlyVerifier(rootsOf(c.fixture), undefined, { freshnessMaxAgeMs: 1 });
    expect(tight.freshnessMaxAgeMs).toBe(1);
    const later = new Date(c.at.getTime() + 1000);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, { repo: c.repo }, later)).resolves.toBeDefined();
    const err = await tight.verifyV3At(c.doc, c.nonce, { repo: c.repo }, later).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/freshness/);
  });
});

describe("Verifier.create config trust and policy", () => {
  const artifact = (format: string): Uint8Array => utf8(JSON.stringify({ format, measurements: {}, machines: {}, policies: {} }));

  it("defaults to a seven-day freshness window, no pins and endorsement-authorized configs", async () => {
    const v = await Verifier.create();
    expect(v.freshnessMaxAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(v.pinnedRegisters).toBeUndefined();
    // The policy can't be reported differently from how it is enforced.
    expect(() => ((v as { freshnessMaxAgeMs: number }).freshnessMaxAgeMs = 1)).toThrow(TypeError);
    expect(() => v.checkPinVerifiability({ repo: "tinfoilsh/repo@v1.0.0" })).not.toThrow();
    expect(() => v.checkPinVerifiability({ repo: "no slash" })).toThrow(UsageError);
    // A pin naming nothing is refused under the public registry alone.
    expect(() => v.checkPinVerifiability({})).toThrow(/pin names nothing/);
    const empty = await Verifier.create(undefined, {});
    expect(empty.freshnessMaxAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it("rejects an invalid field as a usage error", async () => {
    await expect(Verifier.create(undefined, { freshnessMaxAgeMs: -1 })).rejects.toThrow(UsageError);
    await expect(Verifier.create(undefined, { freshnessMaxAgeMs: Number.NaN })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ kind: "configSigningKeys", keys: [] })).rejects.toThrow(/must not be empty/);
    await expect(Verifier.create({ kind: "configSigningKeys", keys: ["not a pem"] })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ kind: "configSigningKeys", keys: "not a list" as unknown as string[] })).rejects.toThrow(/list of PEM strings/);
    await expect(Verifier.create(undefined, { artifacts: { kind: "endorsedArtifacts", freshnessKeys: ["not a pem"] } })).rejects.toThrow(UsageError);
    await expect(Verifier.create(undefined, { artifacts: { kind: "endorsedArtifacts", freshnessKeys: [] } })).rejects.toThrow(/must not be empty/);
    await expect(Verifier.create(undefined, { pinnedRegisters: { platform: "sev-snp", launch: new Uint8Array(3) } })).rejects.toThrow(UsageError);
    await expect(Verifier.create(undefined, { pinnedRegisters: { platform: "other" } as unknown as Expected })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ kind: "configAuthorizer", authorize: "yes" as unknown as () => void })).rejects.toThrow(UsageError);
    await expect(Verifier.create(undefined, { artifacts: { kind: "embeddedArtifacts" } })).rejects.toThrow(/runtime or a platform/);
    await expect(Verifier.create(undefined, { artifacts: { kind: "embeddedArtifacts", platform: artifact(ARTIFACT_FORMAT) } })).rejects.toThrow(/platform-endorsements\/v2/);
    await expect(Verifier.create(undefined, { artifacts: { kind: "embeddedArtifacts", runtime: utf8("{}") } })).rejects.toThrow(UsageError);
    await expect(Verifier.create(undefined, { artifacts: { kind: "embeddedArtifacts", runtime: "{}" as unknown as Uint8Array } })).rejects.toThrow(/must be a Uint8Array/);
    await expect(Verifier.create({ kind: "embeddedConfig", bytes: utf8("name: app\n") })).rejects.toThrow(UsageError);
  });

  it("rejects an unknown kind, a value without one, or a missing member from untyped code as a usage error", async () => {
    for (const bad of [{ kind: "public" }, { ids: [PUBLIC_REGISTRY_ID] }, "registries", null, { kind: "registries" }, { kind: "configSigningKeys" }, { kind: "configAuthorizer" }, { kind: "embeddedConfig" }, { kind: "embeddedConfigReference" }]) {
      await expect(Verifier.create(bad as unknown as ConfigTrust)).rejects.toThrow(UsageError);
    }
    await expect(Verifier.create({ kind: "public" } as unknown as ConfigTrust)).rejects.toThrow(/config trust must have kind/);
    for (const bad of [{ kind: "embedded" }, {}, "endorsedArtifacts", null]) {
      await expect(Verifier.create(undefined, { artifacts: bad as unknown as ArtifactTrust })).rejects.toThrow(UsageError);
    }
    await expect(Verifier.create(undefined, { artifacts: { kind: "embedded" } as unknown as ArtifactTrust })).rejects.toThrow(/artifact trust must have kind/);
    await expect(Verifier.create(undefined, "policy" as unknown as Policy)).rejects.toThrow(/policy must be an object/);
  });

  it("refuses freshness keys when both artifacts are embedded, since nothing is left for them to verify", async () => {
    const pem = (await newSigner()).pem;
    const register = "cd".repeat(48);
    const manifest = utf8(JSON.stringify({ version: "v1.2.3", igvm: { format_version: 1, snp_launch: { measurement: register } } }));
    await expect(
      Verifier.create(undefined, { artifacts: { kind: "embeddedArtifacts", runtime: manifest, platform: artifact(ARTIFACT_FORMAT_V2), freshnessKeys: [pem] } }),
    ).rejects.toThrow(/no endorsed artifact to verify/);
    await expect(Verifier.create(undefined, { artifacts: { kind: "embeddedArtifacts", platform: artifact(ARTIFACT_FORMAT_V2), freshnessKeys: [pem] } })).resolves.toBeDefined();
  });

  it("accepts an embedded v2 platform artifact and derives the config reference from embedded config bytes", async () => {
    const platform = await Verifier.create(undefined, { artifacts: { kind: "embeddedArtifacts", platform: artifact(ARTIFACT_FORMAT_V2) } });
    expect(() => platform.checkPinVerifiability({ project: "org/project@r1" })).not.toThrow();
    const config = utf8(`name: app\ncvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`);
    const embedded = await Verifier.create({ kind: "embeddedConfig", name: "/org/project/r1", bytes: config });
    expect(() => embedded.checkPinVerifiability({})).not.toThrow();
    expect(() => embedded.checkPinVerifiability({ project: "org/project@r1" })).not.toThrow();
    expect(() => embedded.checkPinVerifiability({ project: "org/other@r1" })).toThrow(/embedded config does not match/);
    await expect(Verifier.create({ kind: "embeddedConfig", name: "bad name", bytes: config })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ kind: "embeddedConfig", name: 7 as unknown as string, bytes: config })).rejects.toThrow(/name must be a string/);
  });

  it("accepts an embedded config reference in place of the config bytes", async () => {
    const register = "cd".repeat(48);
    const manifest = utf8(
      JSON.stringify({
        version: "v1.2.3",
        igvm: { format_version: 1, snp_launch: { measurement: register }, tdx_launch: { mrtd: register, rtmr0: "0".repeat(96), rtmr1: "0".repeat(96), rtmr2: "0".repeat(96), rtmr3: "0".repeat(96) } },
      }),
    );
    const runtime: RuntimeReference = { repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: toHex(await sha256(manifest)) };
    const digest = "a".repeat(64);
    const reference: EmbeddedConfigReference = { kind: "embeddedConfigReference", name: "/org/project/r1", digest, runtime };
    const embeddedRuntime: Policy = { artifacts: { kind: "embeddedArtifacts", runtime: manifest } };
    const v = await Verifier.create(reference, embeddedRuntime);
    expect(() => v.checkPinVerifiability({})).not.toThrow();
    expect(() => v.checkPinVerifiability({ project: `org/project@r1@sha256:${digest}` })).not.toThrow();
    expect(() => v.checkPinVerifiability({ project: "org/project@r2" })).toThrow(/embedded config does not match/);
    expect(() => v.checkPinVerifiability({ project: `org/project@sha256:${"b".repeat(64)}` })).toThrow(/embedded config does not match/);
    // Without a name the reference has no identity, so any repository reference, which always
    // pins an identity, mismatches even when its digest agrees; only the empty reference fits.
    const unnamed = await Verifier.create({ kind: "embeddedConfigReference", digest, runtime });
    expect(() => unnamed.checkPinVerifiability({ project: `org/project@sha256:${digest}` })).toThrow(/embedded config does not match/);
    expect(() => unnamed.checkPinVerifiability({})).not.toThrow();
    const bytes = utf8(`cvm-version: v1.2.3@sha256:${runtime.digest}\n`);
    await expect(Verifier.create({ kind: "embeddedConfig", bytes: "config" as unknown as Uint8Array })).rejects.toThrow(/must be a Uint8Array/);
    // The reference is validated like one derived from config bytes, and the embedded manifest must be the one it pins.
    for (const bad of [
      { ...reference, digest: "" },
      { ...reference, digest: "A".repeat(64) },
      { ...reference, name: "/invalid" },
      { ...reference, runtime: { ...runtime, repo: "other/runtime" } },
      { ...reference, runtime: { ...runtime, tag: "1.2.3" } },
      { ...reference, runtime: { ...runtime, digest: "cd".repeat(32) } },
      { ...reference, runtime: "v1.2.3" as unknown as RuntimeReference },
      { ...reference, digest: 7 as unknown as string },
    ]) {
      await expect(Verifier.create(bad, embeddedRuntime)).rejects.toThrow(UsageError);
    }
    // A later change to the caller's object does not reach the verifier.
    const mutable = { kind: "embeddedConfigReference" as const, name: "/org/project/r1", digest, runtime: { ...runtime } };
    const copied = await Verifier.create(mutable);
    mutable.digest = "b".repeat(64);
    mutable.runtime.digest = "cd".repeat(32);
    expect(() => copied.checkPinVerifiability({ project: `org/project@r1@sha256:${digest}` })).not.toThrow();
    // Nor does a later change to embedded config bytes: the reference was settled from a copy.
    const fromBytes = await Verifier.create({ kind: "embeddedConfig", name: "/org/project/r1", bytes });
    const bytesDigest = toHex(await sha256(bytes));
    bytes.fill(0);
    expect(() => fromBytes.checkPinVerifiability({ project: `org/project@r1@sha256:${bytesDigest}` })).not.toThrow();
    // Like every configured trust source, it needs config collateral.
    if (withoutVectors) return;
    const fixture = loadFixture("golden/golden-happy.json");
    const embedded = await dangerousTestOnlyVerifier(rootsOf(fixture), reference);
    const err = await embedded.verifyV3At(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""), {}, clockOf(fixture)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/configured trust requires/);
  });

  it("validates and copies registry IDs", async () => {
    const privateRegistryID = "https://registry.tinfoil.sh/scopes/9c4a7f21e0b836d56a13c8fe42d907ab";
    const ids = [privateRegistryID, "https://registry.tinfoil.sh/scopes/public"];
    const pinned = await Verifier.create({ kind: "registries", ids });
    ids.length = 0;
    expect(() => pinned.checkPinVerifiability({ project: "org/project@r1" })).not.toThrow();
    await expect(Verifier.create({ kind: "registries", ids: [] })).rejects.toThrow(/must not be empty/);
    await expect(Verifier.create({ kind: "registries", ids: [privateRegistryID, privateRegistryID] })).rejects.toThrow(/duplicate/);
    await expect(Verifier.create({ kind: "registries", ids: ["https://example.invalid/scope"] })).rejects.toThrow(/canonical registry URI/);
    await expect(Verifier.create({ kind: "registries", ids: "public" as unknown as string[] })).rejects.toThrow(UsageError);
  });

  it("requires config collateral once registry IDs are pinned", async () => {
    if (withoutVectors) return;
    const fixture = loadFixture("golden/golden-happy.json");
    const pinned = await dangerousTestOnlyVerifier(rootsOf(fixture), { kind: "registries", ids: ["https://registry.tinfoil.sh/scopes/public"] });
    const err = await pinned.verifyV3At(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""), { repo: repoOf(fixture) }, clockOf(fixture)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/configured trust requires/);
  });

  it("refuses a project pin under a config authorizer, which authenticates no name", async () => {
    const authorizer = await Verifier.create({ kind: "configAuthorizer", authorize: () => undefined });
    expect(() => authorizer.checkPinVerifiability({ project: "org/project" })).toThrow(/enforce them in caller policy/);
    expect(() => authorizer.checkPinVerifiability({})).not.toThrow();
  });
});

describe("the document's collateral selects the part of the pin that applies", () => {
  const nonce = new Uint8Array(NONCE_SIZE);
  const repositoryOnly = "only a GitHub repository is pinned";
  const projectOnly = "only a registry project is pinned";
  const repo: Pin = { repo: "org/project" };
  const project: Pin = { project: "org/project" };
  const both: Pin = { repo: "org/project", project: "org/project" };
  // A document without collateral: a pin its collateral format accepts gets as
  // far as the missing code or config entry, and any other stops before it.
  const document = async (collateralFormat: string): Promise<Uint8Array> =>
    (await buildDocument({ nonce, collateralFormat }, () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: utf8("quote") }))).bytes;

  it.each([
    ["repository collateral, repository", FORMAT_V2, repo, SIGSTORE_CODE_V1_FORMAT],
    ["unversioned collateral, repository", "", repo, SIGSTORE_CODE_V1_FORMAT],
    ["repository collateral, project", FORMAT_V2, project, projectOnly],
    ["unversioned collateral, project", "", project, projectOnly],
    ["repository collateral, both", FORMAT_V2, both, SIGSTORE_CODE_V1_FORMAT],
    ["registry collateral, project", FORMAT_V3, project, CONFIG_ID],
    ["registry collateral, repository", FORMAT_V3, repo, repositoryOnly],
    ["registry collateral, both", FORMAT_V3, both, CONFIG_ID],
  ])("%s", async (_name, format, pin, want) => {
    const v = await Verifier.create();
    const err = await v.verifyV3(await document(format), nonce, pin).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toContain(want);
  });

  it("rejects a malformed pin as a usage error whichever collateral the document carries", async () => {
    const v = await Verifier.create();
    for (const format of [FORMAT_V2, FORMAT_V3]) {
      const doc = await document(format);
      for (const pin of [{}, { repo: "not a reference" }, { project: "not a reference" }, { repo: "org/project", project: "not a reference" }, { repo: "not a reference", project: "org/project" }]) {
        await expect(v.verifyV3(doc, nonce, pin)).rejects.toThrow(UsageError);
      }
    }
  });

  it("keeps the configured-trust rejection for repository collateral under registry-only trust", async () => {
    const v = await Verifier.create({ kind: "registries", ids: [PUBLIC_REGISTRY_ID] });
    for (const pin of [{}, project, both]) {
      const err = await v.verifyV3(await document(FORMAT_V2), nonce, pin).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VerificationError);
      expect((err as VerificationError).layer).toBe("provenance");
      expect((err as Error).message).toMatch(/configured trust requires/);
    }
  });

  it("holds registry collateral to the config identity rules a pin check cannot apply without the document", async () => {
    const v = await Verifier.create();
    expect(() => v.checkPinVerifiability({ project: "Org/My_Repo" })).not.toThrow();
    const run = v.verifyV3(await document(FORMAT_V3), nonce, { project: "Org/My_Repo" });
    await expect(run).rejects.toThrow(UsageError);
  });
});

describe("checkPinVerifiability", () => {
  const config = utf8(`name: app\ncvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`);
  const embedded: ConfigTrust = { kind: "embeddedConfig", name: "/org/project/v1", bytes: config };
  const authorizer: ConfigTrust = { kind: "configAuthorizer", authorize: () => undefined };
  const registries: ConfigTrust = { kind: "registries", ids: [PUBLIC_REGISTRY_ID] };

  it.each<[string, ConfigTrust | undefined, Pin, boolean]>([
    ["defaults with a project", undefined, { project: "org/repo@v1" }, true],
    ["defaults with a repository", undefined, { repo: "Org/My_Repo" }, true],
    ["defaults with both", undefined, { repo: "Org/My_Repo", project: "org/project" }, true],
    ["defaults without a pin", undefined, {}, false],
    ["defaults with empty parts", undefined, { repo: "", project: "" }, false],
    ["registry IDs without a pin", registries, {}, true],
    ["defaults with a malformed project", undefined, { project: "not a reference" }, false],
    ["defaults with a malformed repository", undefined, { repo: "not a reference" }, false],
    ["embedded config without a pin", embedded, {}, true],
    ["embedded config with its own project", embedded, { project: "org/project@v1" }, true],
    ["embedded config with another project", embedded, { project: "org/repo" }, false],
    ["embedded config with a repository alone", embedded, { repo: "org/project" }, false],
    ["embedded config with its own project and a repository", embedded, { repo: "org/project", project: "org/project@v1" }, true],
    ["registry IDs with a repository alone", registries, { repo: "org/project" }, false],
    ["registry IDs with a repository and a project", registries, { repo: "org/project", project: "org/project" }, true],
    ["config authorizer without a pin", authorizer, {}, true],
    ["config authorizer with a project", authorizer, { project: "org/repo" }, false],
    ["config authorizer with a repository", authorizer, { repo: "org/repo" }, false],
  ])("%s", async (_name, config, pin, valid) => {
    const v = await Verifier.create(config);
    if (valid) expect(() => v.checkPinVerifiability(pin)).not.toThrow();
    else expect(() => v.checkPinVerifiability(pin)).toThrow(UsageError);
  });
});

describe("config registry IDs beyond the public registry", () => {
  const PRIVATE_REGISTRY_ID = REGISTRY_ID_PREFIX + "9c4a7f21e0b836d56a13c8fe42d907ab";
  const GEN_TIME = new Date("2025-06-15T11:00:00Z");
  const register = "cd".repeat(48);
  const manifest = utf8(
    JSON.stringify({
      version: "v1.2.3",
      igvm: { format_version: 1, snp_launch: { measurement: register }, tdx_launch: { mrtd: register, rtmr0: "0".repeat(96), rtmr1: "0".repeat(96), rtmr2: "0".repeat(96), rtmr3: "0".repeat(96) } },
    }),
  );
  const platform = utf8(JSON.stringify({ format: ARTIFACT_FORMAT_V2, measurements: {}, machines: {}, policies: {} }));

  it("accepts the public registry alongside the given registry IDs as one validated list", async () => {
    expect(PUBLIC_REGISTRY_ID).toBe(PUBLIC_REGISTRY_ID_EXPORTED);
    const v = await Verifier.create({ kind: "registries", ids: [PUBLIC_REGISTRY_ID, PRIVATE_REGISTRY_ID] });
    expect(() => v.checkPinVerifiability({ project: "org/project@r1" })).not.toThrow();
    await expect(Verifier.create({ kind: "registries", ids: [PUBLIC_REGISTRY_ID, PUBLIC_REGISTRY_ID] })).rejects.toThrow(/duplicate config registry ID/);
    await expect(Verifier.create({ kind: "registries", ids: [PUBLIC_REGISTRY_ID, PRIVATE_REGISTRY_ID, PRIVATE_REGISTRY_ID] })).rejects.toThrow(/duplicate config registry ID/);
    await expect(Verifier.create({ kind: "registries", ids: [PUBLIC_REGISTRY_ID, "https://example.invalid/scope"] })).rejects.toThrow(/canonical registry URI/);
    // Once pinned, config collateral is required like any configured trust.
    if (withoutVectors) return;
    const fixture = loadFixture("golden/golden-happy.json");
    const pinned = await dangerousTestOnlyVerifier(rootsOf(fixture), { kind: "registries", ids: [PUBLIC_REGISTRY_ID, PRIVATE_REGISTRY_ID] });
    const err = await pinned.verifyV3At(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""), { repo: repoOf(fixture) }, clockOf(fixture)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/configured trust requires/);
  });

  it("accepts a certified approval under a private registry with the option and rejects it without", async () => {
    // A registry whose root is injected as the registry root, a signing key it certifies for the
    // private registry, and a document whose only collateral is that certified config approval.
    const tsa = await newTimestampAuthority();
    const log = await newLog("ecdsa");
    const registry = await newRegistry(GEN_TIME);
    const signer = await newSigner();
    const certificate = await registryCertificate(registry, signer.spki, { registryID: PRIVATE_REGISTRY_ID, now: GEN_TIME });
    const runtimeDigest = toHex(await sha256(manifest));
    const config = utf8(`name: app\ncvm-version: v1.2.3@sha256:${runtimeDigest}\n`);
    const core = {
      _type: IN_TOTO_STATEMENT_V1,
      subject: [{ name: "/org/project/r1", digest: { sha256: toHex(await sha256(config)) } }],
      predicateType: CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2,
      predicate: { scope: PRIVATE_REGISTRY_ID, runtime: { repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: runtimeDigest } },
    };
    const inner = await timestampResponse(tsa, timestampInput("tinfoil-config-freshness/v2\0", toJson(core)), GEN_TIME);
    const statement = { ...core, predicate: { ...core.predicate, freshness: { rfc3161Timestamp: b64(inner) } } };
    const built = await build(signer, log, {
      statement,
      certificate,
      timestampsFor: async (sig) => [await timestampResponse(tsa, sig, GEN_TIME)],
    });
    const data = JSON.stringify({
      endorsement_ref: await endorsementReference(built.payload),
      sigstore_bundle: built.json,
      issuer_certificate_der: b64(registry.rootDer),
    });
    const nonce = new Uint8Array(NONCE_SIZE).fill(7);
    const { bytes } = await buildDocument(
      { nonce, collateralFormat: FORMAT_V3, collateral: [{ id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_ENDORSEMENT_V2_FORMAT, data }] },
      () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: new Uint8Array(1184).fill(1) }),
    );
    const roots = { sigstore: utf8(JSON.stringify(rootJson([log], [authorityJson(tsa)]))), registryRoots: [registry.root.pem] };
    const at = new Date(GEN_TIME.getTime() + 60 * 60 * 1000);
    const verify = async (config: ConfigTrust | undefined): Promise<VerificationError> => {
      const v = await dangerousTestOnlyVerifier(roots, config, { artifacts: { kind: "embeddedArtifacts", runtime: manifest, platform } });
      const err = await v.verifyV3At(bytes, nonce, { project: "org/project@r1" }, at).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VerificationError);
      return err as VerificationError;
    };
    // The config approval passes and the bogus quote fails next, at the quote layer.
    expect((await verify({ kind: "registries", ids: [PUBLIC_REGISTRY_ID, PRIVATE_REGISTRY_ID] })).layer).toBe("quote");
    expect((await verify({ kind: "registries", ids: [PRIVATE_REGISTRY_ID] })).layer).toBe("quote");
    // A list without the private registry, or the public-only default, rejects it at the provenance layer.
    for (const config of [undefined, { kind: "registries", ids: [PUBLIC_REGISTRY_ID] }, { kind: "registries", ids: [PUBLIC_REGISTRY_ID, REGISTRY_ID_PREFIX + "0".repeat(32)] }] as const) {
      const err = await verify(config);
      expect(err.layer).toBe("provenance");
      expect(err.message).toMatch(/registry ID is not accepted by the caller/);
    }
  });
});

describe("config authorizer", () => {
  it("receives the bundle as the member's exact JSON text", async () => {
    // The authorizer sees the collateral before any approval check, so the
    // bundle need not verify: what matters is that it arrives byte for byte.
    const register = "cd".repeat(48);
    const manifest = utf8(
      JSON.stringify({
        version: "v1.2.3",
        igvm: { format_version: 1, snp_launch: { measurement: register }, tdx_launch: { mrtd: register, rtmr0: "0".repeat(96), rtmr1: "0".repeat(96), rtmr2: "0".repeat(96), rtmr3: "0".repeat(96) } },
      }),
    );
    const platform = utf8(JSON.stringify({ format: ARTIFACT_FORMAT_V2, measurements: {}, machines: {}, policies: {} }));
    const config = utf8(`name: app\ncvm-version: v1.2.3@sha256:${toHex(await sha256(manifest))}\n`);
    const bundleText = `{ "mediaType" : "t\\u00e9st\\/é😀" ,\n "n" : [ 18446744073709551616 , 1.0 , {} ], "s" : "}{" }`;
    const data = `{"endorsement_ref":"sha256:${"ab".repeat(32)}","config_base64":${JSON.stringify(b64(config))},"sigstore_bundle":${bundleText}}`;
    const nonce = new Uint8Array(NONCE_SIZE).fill(7);
    const { bytes } = await buildDocument(
      { nonce, collateralFormat: FORMAT_V3, collateral: [{ id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_ENDORSEMENT_V2_FORMAT, data }] },
      () => ({ format: SEV_SNP_REPORT_V1_FORMAT, report: new Uint8Array(1184).fill(1) }),
    );
    let seen: ConfigEndorsement | undefined;
    const v = await Verifier.create(
      {
        kind: "configAuthorizer",
        authorize: (endorsement) => {
          seen = endorsement;
        },
      },
      { artifacts: { kind: "embeddedArtifacts", runtime: manifest, platform } },
    );
    const err = await v.verifyV3At(bytes, nonce, {}, new Date()).catch((e: unknown) => e);
    expect(seen?.bundle).toBe(bundleText);
    const member = utf8(seen!.bundle!);
    const marker = utf8(`"sigstore_bundle":`);
    const start = Buffer.from(bytes).indexOf(Buffer.from(marker)) + marker.length;
    expect(bytes.subarray(start, start + member.length)).toEqual(member);
    expect(bytes[start + member.length]).toBe("}".charCodeAt(0));
    expect(JSON.parse(seen!.bundle!)).toEqual({ mediaType: "tést/é😀", n: [18446744073709552000, 1, {}], s: "}{" });
    expect(seen!.config).toEqual(config);
    // The config was authorized; the bogus quote fails next, at the quote layer.
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("quote");
  });
});
