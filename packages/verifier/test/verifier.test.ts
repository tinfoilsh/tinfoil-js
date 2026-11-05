/**
 * The verification pipeline on the shared full-verify vectors (golden,
 * golden-tdx, freshness, real-frozen): every accept must yield the vector's
 * facts, every rejection must name the vector's layer, and caller mistakes
 * must surface as usage errors rather than rejections.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { expectedOf, measurementOf } from "../conformance/adapter.js";
import { CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_ID, FORMAT_V3, ROLE_REFERENCE_VALUES } from "../src/document/collateral/collateral.js";
import type { ConfigEndorsement } from "../src/document/collateral/config.js";
import type { RuntimeReference } from "../src/document/collateral/runtime.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE, SEV_SNP_REPORT_V1_FORMAT } from "../src/document/document.js";
import { UsageError, VerificationError, type Layer } from "../src/errors.js";
import { sha256, toHex } from "../src/internal/bytes.js";
import { CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2, IN_TOTO_STATEMENT_V1, PUBLIC_REGISTRY_ID, REGISTRY_ID_PREFIX } from "../src/internal/endorsement/approval.js";
import { ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2 } from "../src/internal/policy/artifact.js";
import { endorsementReference, timestampInput } from "../src/internal/sigstore/timestamp.js";
import type { Expected } from "../src/measurement.js";
import { dangerousTestOnlyVerifier, Verifier, type EmbeddedConfigReference, type VerifierOptions } from "../src/verifier.js";
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
          expect(outcome.verified.tlsPublicKeyFP === undefined || outcome.verified.hpkePublicKey === undefined).toBe(true);
          return;
        }
        expect(outcome.err).toBeInstanceOf(VerificationError);
        expect((outcome.err as VerificationError).layer).toBe(LAYER_OF[expected.code ?? ""]);
        return;
      }
      const v = await run;
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
      expect(v.metadata.verifiedAt).toEqual(c.at);
      expect(v.metadata.verifier.name).toBe("@tinfoilsh/verifier");
      const expires = v.freshnessExpiresAt;
      expect(expires).toBeDefined();
      expect(expires!.getTime()).toBeGreaterThanOrEqual(c.at.getTime());
      expect(expires!.getTime()).toBeLessThanOrEqual(c.at.getTime() + c.verifier.freshnessMaxAgeMs + 5 * 60 * 1000);
    });
  }
});

describe.skipIf(withoutVectors)(vectorsTitle("the JSON form of a verification"), () => {
  it("pins the shape of the golden vector's facts", async () => {
    const c = await caseOf(loadFixture("golden/golden-happy.json"));
    const v = await c.verifier.verifyV3At(c.doc, c.nonce, c.repo, c.at);
    const launch = "11".repeat(48);
    const json = {
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
    const launch = v.enclaveMeasurement;
    if (launch.platform !== "sev-snp") throw new Error("golden-happy is an SEV-SNP document");
    const matching = await dangerousTestOnlyVerifier(rootsOf(c.fixture), { pinnedRegisters: { platform: "sev-snp", launch: launch.launch } });
    await expect(matching.verifyV3At(c.doc, c.nonce, c.repo, c.at)).resolves.toBeDefined();
    expect(matching.pinnedRegisters).toEqual({ platform: "sev-snp", launch: launch.launch });
    // The pins are one frozen copy: every read is the same object, and the policy keeps its own.
    expect(matching.pinnedRegisters).toBe(matching.pinnedRegisters);
    expect(Object.isFrozen(matching.pinnedRegisters)).toBe(true);
    (matching.pinnedRegisters as { launch: Uint8Array }).launch[0] ^= 0xff;
    await expect(matching.verifyV3At(c.doc, c.nonce, c.repo, c.at)).resolves.toBeDefined();

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
    expect(tight.freshnessMaxAgeMs).toBe(1);
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
    expect(v.freshnessMaxAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(v.pinnedRegisters).toBeUndefined();
    expect(v.callerAuthorizesConfig).toBe(false);
    // The policy can't be reported differently from how it is enforced.
    expect(() => ((v as { callerAuthorizesConfig: boolean }).callerAuthorizesConfig = true)).toThrow(TypeError);
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
    expect(platform.callerAuthorizesConfig).toBe(false);
    const config = utf8(`name: app\ncvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`);
    const embedded = await Verifier.create({ embeddedReferences: { config: { name: "/org/project/r1", bytes: config } } });
    expect(embedded.callerAuthorizesConfig).toBe(true);
    expect(() => embedded.checkRepoVerifiability("org/project@r1")).not.toThrow();
    expect(() => embedded.checkRepoVerifiability("org/other@r1")).toThrow(/embedded config does not match/);
    await expect(Verifier.create({ embeddedReferences: { config: { name: "bad name", bytes: config } } })).rejects.toThrow(UsageError);
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
    const reference: EmbeddedConfigReference = { name: "/org/project/r1", digest, runtime };
    const v = await Verifier.create({ embeddedReferences: { configReference: reference, runtime: manifest } });
    expect(v.callerAuthorizesConfig).toBe(true);
    expect(() => v.checkRepoVerifiability("")).not.toThrow();
    expect(() => v.checkRepoVerifiability(`org/project@r1@sha256:${digest}`)).not.toThrow();
    expect(() => v.checkRepoVerifiability("org/project@r2")).toThrow(/embedded config does not match/);
    expect(() => v.checkRepoVerifiability(`org/project@sha256:${"b".repeat(64)}`)).toThrow(/embedded config does not match/);
    // Without a name the reference has no identity, so any repository reference, which always
    // pins an identity, mismatches even when its digest agrees; only the empty reference fits.
    const unnamed = await Verifier.create({ embeddedReferences: { configReference: { digest, runtime } } });
    expect(() => unnamed.checkRepoVerifiability(`org/project@sha256:${digest}`)).toThrow(/embedded config does not match/);
    expect(() => unnamed.checkRepoVerifiability("")).not.toThrow();
    // The two forms of an embedded config are exclusive.
    const bytes = utf8(`cvm-version: v1.2.3@sha256:${runtime.digest}\n`);
    await expect(Verifier.create({ embeddedReferences: { config: { bytes }, configReference: reference } })).rejects.toThrow(/mutually exclusive/);
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
      await expect(Verifier.create({ embeddedReferences: { configReference: bad, runtime: manifest } })).rejects.toThrow(UsageError);
    }
    // A later change to the caller's object does not reach the verifier.
    const mutable = { name: "/org/project/r1", digest, runtime: { ...runtime } };
    const copied = await Verifier.create({ embeddedReferences: { configReference: mutable } });
    mutable.digest = "b".repeat(64);
    mutable.runtime.digest = "cd".repeat(32);
    expect(() => copied.checkRepoVerifiability(`org/project@r1@sha256:${digest}`)).not.toThrow();
    // Nor does a later change to embedded config bytes: the reference was settled from a copy.
    const fromBytes = await Verifier.create({ embeddedReferences: { config: { name: "/org/project/r1", bytes } } });
    const bytesDigest = toHex(await sha256(bytes));
    bytes.fill(0);
    expect(() => fromBytes.checkRepoVerifiability(`org/project@r1@sha256:${bytesDigest}`)).not.toThrow();
    // Like every configured trust source, it needs config collateral.
    if (withoutVectors) return;
    const fixture = loadFixture("golden/golden-happy.json");
    const embedded = await dangerousTestOnlyVerifier(rootsOf(fixture), { embeddedReferences: { configReference: reference } });
    const err = await embedded.verifyV3At(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""), "", clockOf(fixture)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/configured trust requires/);
  });

  it("accepts registry ID pins only alongside registry trust", async () => {
    const privateRegistryID = "https://registry.tinfoil.sh/scopes/9c4a7f21e0b836d56a13c8fe42d907ab";
    const pinned = await Verifier.create({ configRegistryIDs: [privateRegistryID, "https://registry.tinfoil.sh/scopes/public"] });
    expect(pinned.callerAuthorizesConfig).toBe(false);
    expect(() => pinned.checkRepoVerifiability("org/project@r1")).not.toThrow();
    await expect(Verifier.create({ configRegistryIDs: [] })).rejects.toThrow(/must not be empty/);
    await expect(Verifier.create({ configRegistryIDs: [privateRegistryID, privateRegistryID] })).rejects.toThrow(/duplicate/);
    await expect(Verifier.create({ configRegistryIDs: ["https://example.invalid/scope"] })).rejects.toThrow(/canonical registry URI/);
    await expect(Verifier.create({ configRegistryIDs: "public" as unknown as string[] })).rejects.toThrow(UsageError);
    const { pem } = await newSigner();
    await expect(Verifier.create({ configRegistryIDs: [privateRegistryID], configSigningKeys: [pem] })).rejects.toThrow(/registry root verification/);
    await expect(Verifier.create({ configRegistryIDs: [privateRegistryID], configAuthorizer: () => undefined })).rejects.toThrow(/require endorsement verification/);
    const config = { bytes: utf8(`cvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`) };
    await expect(Verifier.create({ configRegistryIDs: [privateRegistryID], embeddedReferences: { config } })).rejects.toThrow(/require endorsement verification/);
  });

  it("requires config collateral once registry IDs are pinned", async () => {
    if (withoutVectors) return;
    const fixture = loadFixture("golden/golden-happy.json");
    const pinned = await dangerousTestOnlyVerifier(rootsOf(fixture), { configRegistryIDs: ["https://registry.tinfoil.sh/scopes/public"] });
    const err = await pinned.verifyV3At(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""), repoOf(fixture), clockOf(fixture)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).layer).toBe("provenance");
    expect((err as Error).message).toMatch(/configured trust requires/);
  });

  it("rejects conflicting trust sources", async () => {
    const config = { bytes: utf8(`cvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`) };
    const pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" + "A".repeat(84) + "\n-----END PUBLIC KEY-----\n";
    await expect(Verifier.create({ configAuthorizer: () => undefined, embeddedReferences: { config } })).rejects.toThrow(/conflicts/);
    await expect(Verifier.create({ configAuthorizer: () => undefined, configSigningKeys: [pem] })).rejects.toThrow(UsageError);
    const authorizer = await Verifier.create({ configAuthorizer: () => undefined });
    expect(authorizer.callerAuthorizesConfig).toBe(true);
    expect(() => authorizer.checkRepoVerifiability("org/project")).toThrow(/enforce them in caller policy/);
    expect(() => authorizer.checkRepoVerifiability("")).not.toThrow();
  });
});

describe("additional config registry IDs", () => {
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

  it("accepts the public registry plus the given registry IDs, supplied once and validated as one list", async () => {
    const v = await Verifier.create({ additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID] });
    expect(v.callerAuthorizesConfig).toBe(false);
    expect(() => v.checkRepoVerifiability("org/project@r1")).not.toThrow();
    await expect(Verifier.create({ additionalConfigRegistryIDs: [] })).rejects.toThrow(/additional config registry IDs must not be empty/);
    await expect(Verifier.create({ additionalConfigRegistryIDs: [PUBLIC_REGISTRY_ID] })).rejects.toThrow(/duplicate config registry ID/);
    await expect(Verifier.create({ additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID, PRIVATE_REGISTRY_ID] })).rejects.toThrow(/duplicate config registry ID/);
    await expect(Verifier.create({ additionalConfigRegistryIDs: ["https://example.invalid/scope"] })).rejects.toThrow(/canonical registry URI/);
    await expect(Verifier.create({ additionalConfigRegistryIDs: PRIVATE_REGISTRY_ID as unknown as string[] })).rejects.toThrow(UsageError);
    await expect(Verifier.create({ additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID], configRegistryIDs: [PRIVATE_REGISTRY_ID] })).rejects.toThrow(
      /config registry IDs must be supplied once/,
    );
    // The same trust conflicts as an exact registry ID list.
    const { pem } = await newSigner();
    await expect(Verifier.create({ additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID], configSigningKeys: [pem] })).rejects.toThrow(/registry root verification/);
    await expect(Verifier.create({ additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID], configAuthorizer: () => undefined })).rejects.toThrow(
      /require endorsement verification/,
    );
    const config = { bytes: utf8(`cvm-version: v1.2.3@sha256:${"a".repeat(64)}\n`) };
    await expect(Verifier.create({ additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID], embeddedReferences: { config } })).rejects.toThrow(
      /require endorsement verification/,
    );
    // Once pinned, config collateral is required like any configured trust.
    if (withoutVectors) return;
    const fixture = loadFixture("golden/golden-happy.json");
    const pinned = await dangerousTestOnlyVerifier(rootsOf(fixture), { additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID] });
    const err = await pinned.verifyV3At(inputBytes(fixture, "document_b64"), hex(fixture.input.nonce_hex ?? ""), repoOf(fixture), clockOf(fixture)).catch((e: unknown) => e);
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
    const verify = async (options: VerifierOptions): Promise<VerificationError> => {
      const v = await dangerousTestOnlyVerifier(roots, { embeddedReferences: { runtime: manifest, platform }, ...options });
      const err = await v.verifyV3At(bytes, nonce, "org/project@r1", at).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VerificationError);
      return err as VerificationError;
    };
    // The config approval passes and the bogus quote fails next, at the quote layer.
    expect((await verify({ additionalConfigRegistryIDs: [PRIVATE_REGISTRY_ID] })).layer).toBe("quote");
    expect((await verify({ configRegistryIDs: [PRIVATE_REGISTRY_ID] })).layer).toBe("quote");
    // Public-only trust, explicit or default, rejects the registry at the provenance layer.
    for (const options of [{}, { configRegistryIDs: [PUBLIC_REGISTRY_ID] }, { additionalConfigRegistryIDs: [REGISTRY_ID_PREFIX + "0".repeat(32)] }]) {
      const err = await verify(options);
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
    const v = await Verifier.create({
      embeddedReferences: { runtime: manifest, platform },
      configAuthorizer: (endorsement) => {
        seen = endorsement;
      },
    });
    const err = await v.verifyV3At(bytes, nonce, "", new Date()).catch((e: unknown) => e);
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
