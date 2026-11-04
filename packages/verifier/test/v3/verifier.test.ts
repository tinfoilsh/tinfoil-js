/**
 * The verification pipeline on the shared full-verify vectors (golden,
 * golden-tdx, freshness, real-frozen): every accept must yield the vector's
 * facts, every rejection must name the vector's layer, and caller mistakes
 * must surface as usage errors rather than rejections.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { expectedOf, measurementOf } from "../../conformance/adapter.js";
import { NONCE_SIZE } from "../../src/v3/document/document.js";
import { UsageError, VerificationError, type Layer } from "../../src/v3/errors.js";
import { ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2 } from "../../src/v3/internal/policy/artifact.js";
import type { Expected } from "../../src/v3/measurement.js";
import { dangerousTestOnlyVerifier, Verifier } from "../../src/v3/verifier.js";
import { conformanceAvailable, inputBytes, loadFixture, loadFixtures, repoOf, vectorsTitle, type ConformanceFixture } from "./helpers/conformance.js";
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
      const run = c.verifier.verifyV3At(c.doc, c.nonce, c.repo, c.at);
      if (!expected.accepted) {
        if (expected.code === "MALFORMED_INPUT") {
          await expect(run).rejects.toBeInstanceOf(UsageError);
          return;
        }
        const outcome = await run.then(
          (v) => ({ verified: v }),
          (e: unknown) => ({ err: e }),
        );
        if ("verified" in outcome) {
          // The verifier accepts a document that endorses no usable channel
          // keys; the adapter's full stage, like every real client, then
          // rejects it at the envelope layer.
          expect(expected.code).toBe("ENVELOPE_REJECTED");
          expect(outcome.verified.tlsPublicKeyFP() === undefined || outcome.verified.hpkePublicKey() === undefined).toBe(true);
          return;
        }
        expect(outcome.err).toBeInstanceOf(VerificationError);
        expect((outcome.err as VerificationError).layer).toBe(LAYER_OF[expected.code ?? ""]);
        return;
      }
      const v = await run;
      if (expected.tls_public_key_fp) expect(v.tlsPublicKeyFP()).toBe(expected.tls_public_key_fp);
      if (expected.hpke_public_key) expect(v.hpkePublicKey()).toBe(expected.hpke_public_key);
      if (expected.code_digest) expect(v.codeDigest()).toBe(expected.code_digest);
      if (expected.code_measurement) expect(expectedOf(v.codeMeasurement())).toEqual(expected.code_measurement);
      if (expected.enclave_measurement) expect(measurementOf(v.enclaveMeasurement())).toEqual(expected.enclave_measurement);
      // A code release carries no config, runtime or platform facts, and its
      // witnesses bound the freshness window around the appraisal clock.
      expect(v.configRepo()).toBe(c.repo.split("@")[0]);
      expect(v.codeTag()).not.toBe("");
      expect(v.config()).toBeUndefined();
      expect(v.runtime()).toBeUndefined();
      expect(v.platform()).toBeUndefined();
      expect(v.metadata().verifiedAt).toEqual(c.at);
      expect(v.metadata().verifier.name).toBe("@tinfoilsh/verifier");
      const expires = v.freshnessExpiresAt();
      expect(expires).toBeDefined();
      expect(expires!.getTime()).toBeGreaterThanOrEqual(c.at.getTime());
      expect(expires!.getTime()).toBeLessThanOrEqual(c.at.getTime() + c.verifier.freshnessMaxAgeMs() + 5 * 60 * 1000);
    });
  }
});

describe.skipIf(withoutVectors)(vectorsTitle("verifyV3At caller mistakes"), () => {
  let c: Case;
  beforeAll(async () => {
    c = await caseOf(loadFixture("golden/golden-happy.json"));
  });

  it("rejects a nonce of the wrong length as a usage error, not an envelope rejection", async () => {
    await expect(c.verifier.verifyV3At(c.doc, c.nonce.subarray(1), c.repo, c.at)).rejects.toThrow(UsageError);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce.subarray(1), c.repo, c.at)).rejects.toThrow(/expected nonce must be 32 bytes/);
  });

  it("rejects an invalid verification time", async () => {
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, c.repo, new Date(NaN))).rejects.toThrow(UsageError);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, c.repo, "2025-01-01" as unknown as Date)).rejects.toThrow(UsageError);
  });

  it("rejects a malformed repository reference as a usage error", async () => {
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, "not a repo", c.at)).rejects.toThrow(UsageError);
  });

  it("rejects a different nonce at the envelope layer", async () => {
    const other = new Uint8Array(NONCE_SIZE).fill(7);
    const err = await c.verifier.verifyV3At(c.doc, other, c.repo, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("envelope");
  });

  it("rejects another repository at the provenance layer", async () => {
    const err = await c.verifier.verifyV3At(c.doc, c.nonce, "tinfoilsh/other-repo", c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
  });

  it("requires config collateral once the policy pins config trust", async () => {
    const verifier = await dangerousTestOnlyVerifier(rootsOf(c.fixture), { configAuthorizer: () => undefined });
    const err = await verifier.verifyV3At(c.doc, c.nonce, c.repo, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/configured trust requires/);
  });

  it("applies pinned registers: a matching pin passes, a conflicting or foreign one rejects at the policy layer", async () => {
    const v = await c.verifier.verifyV3At(c.doc, c.nonce, c.repo, c.at);
    const launch = v.enclaveMeasurement();
    if (launch.platform !== "sev-snp") throw new Error("golden-happy is an SEV-SNP document");
    const matching = await dangerousTestOnlyVerifier(rootsOf(c.fixture), { pinnedRegisters: { platform: "sev-snp", launch: launch.launch } });
    await expect(matching.verifyV3At(c.doc, c.nonce, c.repo, c.at)).resolves.toBeDefined();
    expect(matching.pinnedRegisters()).toEqual({ platform: "sev-snp", launch: launch.launch });

    const conflicting = await dangerousTestOnlyVerifier(rootsOf(c.fixture), { pinnedRegisters: { platform: "sev-snp", launch: new Uint8Array(48).fill(9) } });
    const err = await conflicting.verifyV3At(c.doc, c.nonce, c.repo, c.at).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("policy");
    expect((err as Error).message).toMatch(/pinned launch measurement does not match/);

    const foreign = await dangerousTestOnlyVerifier(rootsOf(c.fixture), { pinnedRegisters: { platform: "tdx", rtmr3: new Uint8Array(48) } });
    const err2 = await foreign.verifyV3At(c.doc, c.nonce, c.repo, c.at).catch((e: unknown) => e);
    expect((err2 as VerificationError).layer).toBe("policy");
    expect((err2 as Error).message).toMatch(/pinned registers are for tdx, but the enclave is sev-snp/);
  });

  it("enforces the freshness window it was built with", async () => {
    // The witnesses were logged at the vector's clock; one second later a
    // one-millisecond window no longer covers them.
    const tight = await dangerousTestOnlyVerifier(rootsOf(c.fixture), { freshnessMaxAgeMs: 1 });
    expect(tight.freshnessMaxAgeMs()).toBe(1);
    const later = new Date(c.at.getTime() + 1000);
    await expect(c.verifier.verifyV3At(c.doc, c.nonce, c.repo, later)).resolves.toBeDefined();
    const err = await tight.verifyV3At(c.doc, c.nonce, c.repo, later).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/freshness/);
  });
});

describe("Verifier.create options", () => {
  const artifact = (format: string): Uint8Array => utf8(JSON.stringify({ format, measurements: {}, machines: {}, policies: {} }));

  it("defaults to a seven-day freshness window, no pins and endorsement-authorized configs", async () => {
    const v = await Verifier.create();
    expect(v.freshnessMaxAgeMs()).toBe(7 * 24 * 60 * 60 * 1000);
    expect(v.pinnedRegisters()).toBeUndefined();
    expect(v.callerAuthorizesConfig()).toBe(false);
    expect(() => v.checkRepoVerifiability("tinfoilsh/repo@v1.0.0")).not.toThrow();
    expect(() => v.checkRepoVerifiability("no slash")).toThrow(UsageError);
  });

  it("rejects invalid options as usage errors", async () => {
    await expect(Verifier.create({ freshnessMaxAgeMs: -1 })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ freshnessMaxAgeMs: Number.NaN })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ configSigningKeys: [] })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ configSigningKeys: ["not a pem"] })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ freshnessSigningKeys: ["not a pem"] })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ pinnedRegisters: { platform: "sev-snp", launch: new Uint8Array(3) } })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ pinnedRegisters: { platform: "other" } as unknown as Expected })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ configAuthorizer: "yes" as unknown as () => void })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ embeddedReferences: {} })).rejects.toThrow(/at least one component/);
    await expect(Verifier.create({ embeddedReferences: { platform: artifact(ARTIFACT_FORMAT) } })).rejects.toThrow(/platform-endorsements\/v2/);
    await expect(Verifier.create({ embeddedReferences: { runtime: utf8("{}") } })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ embeddedReferences: { config: { bytes: utf8("name: app\n") } } })).rejects.toThrow(UsageError);
  });

  it("accepts an embedded v2 platform artifact and derives the config reference from embedded config bytes", async () => {
    const platform = await Verifier.create({ embeddedReferences: { platform: artifact(ARTIFACT_FORMAT_V2) } });
    expect(platform.callerAuthorizesConfig()).toBe(false);
    const config = utf8(`name: app\ncvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`);
    const embedded = await Verifier.create({ embeddedReferences: { config: { name: "/org/project/r1", bytes: config } } });
    expect(embedded.callerAuthorizesConfig()).toBe(true);
    expect(() => embedded.checkRepoVerifiability("org/project@r1")).not.toThrow();
    expect(() => embedded.checkRepoVerifiability("org/other@r1")).toThrow(/embedded config does not match/);
    await expect(Verifier.create({ embeddedReferences: { config: { name: "bad name", bytes: config } } })).rejects.toThrow(UsageError);
  });

  it("rejects conflicting trust sources", async () => {
    const config = { bytes: utf8(`cvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`) };
    const pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" + "A".repeat(84) + "\n-----END PUBLIC KEY-----\n";
    await expect(Verifier.create({ configAuthorizer: () => undefined, embeddedReferences: { config } })).rejects.toThrow(/conflicts/);
    await expect(Verifier.create({ configAuthorizer: () => undefined, configSigningKeys: [pem] })).rejects.toThrow(UsageError);
    const authorizer = await Verifier.create({ configAuthorizer: () => undefined });
    expect(authorizer.callerAuthorizesConfig()).toBe(true);
    expect(() => authorizer.checkRepoVerifiability("org/project")).toThrow(/enforce them in caller policy/);
    expect(() => authorizer.checkRepoVerifiability("")).not.toThrow();
  });
});
