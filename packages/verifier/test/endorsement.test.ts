/**
 * Tests for the certificate-signed half of the endorsement layer: release
 * references (reference.ts), code and platform provenance (provenance.ts),
 * the freshness witness (freshness.ts) and the runtime release (runtime.ts).
 *
 * The shared tinfoil-conformance vectors drive the provenance and policy
 * suites: every `provenance/*.json` (stage v3-authenticate-provenance) and
 * `policy/*.json` (stage v3-assemble-policy) vector carries a document whose
 * sigstore-code or sigstore-platform bundle is authenticated here with the
 * vector's root and expected verdict, and `freshness/*.json` documents carry
 * the code witnesses the freshness suite judges at the vector's clock. The
 * runtime release has no vector yet, so only its pure checks run.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { dangerousTestOnlyDecode } from "../conformance/testing.js";
import * as document from "../src/document/document.js";
import { utf8 } from "../src/internal/bytes.js";
import {
  authenticateFreshness,
  FRESHNESS_PREDICATE_FORMAT,
  MAX_FRESHNESS_AGE_MS,
  MAX_FRESHNESS_FUTURE_SKEW_MS,
  parseFreshnessStatement,
  validateFreshnessTime,
  validateWitness,
} from "../src/internal/endorsement/freshness.js";
import { promisedLogTime } from "../src/internal/sigstore/keyed.js";
import {
  FRESHNESS_WITNESS_IDENTITY,
  MULTI_PLATFORM_PREDICATE_TYPE,
  PLATFORM_ENDORSEMENTS_IDENTITY,
  PLATFORM_ENDORSEMENTS_REPO,
  ProvenanceClient,
  signedPredicate,
  signingIdentity,
  type Code,
} from "../src/internal/endorsement/provenance.js";
import { parseReference, validateAuthenticatedArtifact, type AuthenticatedArtifact } from "../src/internal/endorsement/reference.js";
import { authenticateRuntime, runtimeIdentity, runtimeSubjectName } from "../src/internal/endorsement/runtime.js";
import { strictParse, type JsonValue } from "../src/internal/json/index.js";
import { parseBundle, type TlogEntry } from "../src/internal/sigstore/bundle.js";
import { registerHex } from "../src/measurement.js";
import { ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2 } from "../src/internal/policy/artifact.js";
import {
  conformanceAvailable,
  inputBytes,
  loadFixture,
  loadFixtures,
  repoOf,
  trustedRootBytes,
  vectorsTitle,
  verificationTime,
  type ConformanceFixture,
} from "./helpers/conformance.js";

const withoutVectors = !conformanceAvailable();
// Read at collection time only when the checkout is present, so the suites skip instead of failing without it.
const PROVENANCE_VECTORS = withoutVectors ? [] : loadFixtures("provenance");
const POLICY_VECTORS = withoutVectors ? [] : loadFixtures("policy");
const FRESHNESS_VECTORS = withoutVectors ? [] : loadFixtures("freshness");

// ---------------------------------------------------------------- references

describe("parseReference", () => {
  it("splits owner/name[@tag][@sha256:digest]", () => {
    const digest = "f".repeat(64);
    expect(parseReference("tinfoilsh/model")).toEqual({ repo: "tinfoilsh/model", tag: "", digest: "" });
    expect(parseReference("tinfoilsh/model@v1.2.3")).toEqual({ repo: "tinfoilsh/model", tag: "v1.2.3", digest: "" });
    expect(parseReference(`tinfoilsh/model@sha256:${digest}`)).toEqual({ repo: "tinfoilsh/model", tag: "", digest });
    expect(parseReference(`tinfoilsh/model@v1@sha256:${digest}`)).toEqual({ repo: "tinfoilsh/model", tag: "v1", digest });
    expect(parseReference("a.b-c_d/e.f-g_h@release/2025.01")).toEqual({ repo: "a.b-c_d/e.f-g_h", tag: "release/2025.01", digest: "" });
  });

  it("rejects malformed references", () => {
    for (const bad of ["", "model", "tinfoilsh/", "/model", "tinfoilsh/model@", "tinfoilsh/model@v1@v2", "tinfoilsh/model@sha256:abc", "owner/name@tag with space", "owner/name@ta~g", `owner/name@sha256:${"F".repeat(64)}`]) {
      expect(() => parseReference(bad), bad).toThrow(/invalid release reference/);
    }
  });
});

describe("validateAuthenticatedArtifact", () => {
  const good: AuthenticatedArtifact = { repo: "tinfoilsh/model", tag: "v1", commit: "a".repeat(40), subjectName: "model.tar", digest: "b".repeat(64) };
  it("requires every field to be well formed", () => {
    expect(() => validateAuthenticatedArtifact(good)).not.toThrow();
    expect(() => validateAuthenticatedArtifact({ ...good, repo: "model" })).toThrow(/repository/);
    expect(() => validateAuthenticatedArtifact({ ...good, tag: "" })).toThrow(/tag/);
    expect(() => validateAuthenticatedArtifact({ ...good, commit: "A".repeat(40) })).toThrow(/commit/);
    expect(() => validateAuthenticatedArtifact({ ...good, subjectName: "" })).toThrow(/subject name/);
    expect(() => validateAuthenticatedArtifact({ ...good, digest: "b".repeat(63) })).toThrow(/digest/);
  });
});

// ---------------------------------------------------------------- identities

describe("signing identities", () => {
  it("accepts a tag-ref workflow of the repository and nothing else", () => {
    const p = signingIdentity("tinfoilsh/model");
    expect(p.test("https://github.com/tinfoilsh/model/.github/workflows/release.yml@refs/tags/v1")).toBe(true);
    expect(p.test("https://github.com/tinfoilsh/model/.github/workflows/release.yml@refs/heads/main")).toBe(false);
    expect(p.test("https://github.com/tinfoilsh/model/.github/workflows/sub/release.yml@refs/tags/v1")).toBe(false);
    expect(p.test("https://github.com/tinfoilsh/model2/.github/workflows/release.yml@refs/tags/v1")).toBe(false);
    expect(p.test("https://github.com/tinfoilsh/model/.github/workflows/release.yml@refs/tags/v1@x")).toBe(false);
    expect(p.test("xhttps://github.com/tinfoilsh/model/.github/workflows/release.yml@refs/tags/v1")).toBe(false);
    expect(() => signingIdentity("model")).toThrow(/invalid repository name/);
    expect(() => signingIdentity("tinfoilsh/model/extra")).toThrow(/invalid repository name/);
  });

  it("anchors the pinned platform and witness identities", () => {
    expect(PLATFORM_ENDORSEMENTS_IDENTITY.test(`https://github.com/${PLATFORM_ENDORSEMENTS_REPO}/.github/workflows/platform-release.yml@refs/tags/platform-v1.2.3`)).toBe(true);
    expect(PLATFORM_ENDORSEMENTS_IDENTITY.test(`https://github.com/${PLATFORM_ENDORSEMENTS_REPO}/.github/workflows/platform-release.yml@refs/tags/v1.2.3`)).toBe(false);
    expect(PLATFORM_ENDORSEMENTS_IDENTITY.test(`https://github.com/${PLATFORM_ENDORSEMENTS_REPO}/.github/workflows/platform-releaseXyml@refs/tags/platform-v1`)).toBe(false);
    expect(FRESHNESS_WITNESS_IDENTITY.test("https://github.com/tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main")).toBe(true);
    expect(FRESHNESS_WITNESS_IDENTITY.test("https://github.com/tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main2")).toBe(false);
    expect(runtimeIdentity("v1.2.3").test("https://github.com/tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/v1.2.3")).toBe(true);
    expect(runtimeIdentity("v1.2.3").test("https://github.com/tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/v1.2.34")).toBe(false);
    expect(runtimeSubjectName("v1.2.3")).toBe("tinfoil-inference-v1.2.3-manifest.json");
  });
});

// ---------------------------------------------------------------- vectors

async function clientOf(fixture: ConformanceFixture): Promise<ProvenanceClient> {
  const rootBytes = trustedRootBytes(fixture);
  return rootBytes === undefined ? ProvenanceClient.default() : ProvenanceClient.fromJSON(rootBytes);
}

const documentOf = (fixture: ConformanceFixture): Promise<document.Document> => dangerousTestOnlyDecode(inputBytes(fixture, "document_b64"));
const clockOf = (fixture: ConformanceFixture): Date => {
  const unix = verificationTime(fixture);
  return unix === undefined ? new Date() : new Date(unix * 1000);
};

async function authenticateCodeOf(fixture: ConformanceFixture): Promise<Code> {
  const doc = await documentOf(fixture);
  const ref = doc.sigstoreCode();
  return (await clientOf(fixture)).authenticateCode(ref.bundle, parseReference(repoOf(fixture)), ref.tag, ref.digest);
}

describe.skipIf(withoutVectors)(vectorsTitle("ProvenanceClient.authenticateCode"), () => {
  for (const fixture of PROVENANCE_VECTORS) {
    const { expected } = fixture;
    it(`${fixture.id}: ${expected.accepted ? "accepts" : "rejects"}`, async () => {
      if (!expected.accepted) {
        await expect(authenticateCodeOf(fixture)).rejects.toThrow();
        return;
      }
      const code = await authenticateCodeOf(fixture);
      expect(code.digest).toBe(expected.code_digest);
      const measurement = expected.code_measurement as { type: string; registers: string[] };
      expect(measurement.type).toBe(MULTI_PLATFORM_PREDICATE_TYPE);
      expect([code.sevSnp.launch, code.tdx.rtmr1, code.tdx.rtmr2].map((r) => registerHex(r!))).toEqual(measurement.registers);
      expect(code.repo).toBe(parseReference(repoOf(fixture)).repo);
      expect(code.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(code.tag).not.toBe("");
      expect(code.subjectName).not.toBe("");
      expect(code.shape.cpus).toBeGreaterThan(0n);
    });
  }

  it("lets the reference's pins override the document's tag and digest hints", async () => {
    const fixture = loadFixture("provenance/provenance-happy.json");
    const doc = await documentOf(fixture);
    const ref = doc.sigstoreCode();
    const client = await clientOf(fixture);
    const repo = parseReference(repoOf(fixture)).repo;
    const code = await client.authenticateCode(ref.bundle, { repo, tag: "", digest: "" }, ref.tag, ref.digest);
    // Pins replace the hints; without pins, the hints must be right.
    expect((await client.authenticateCode(ref.bundle, { repo, tag: code.tag, digest: ref.digest }, "wrong-tag-hint", "0".repeat(64))).digest).toBe(ref.digest);
    await expect(client.authenticateCode(ref.bundle, { repo, tag: "", digest: "" }, ref.tag, "0".repeat(64))).rejects.toThrow(/does not match expected artifact digest/);
    await expect(client.authenticateCode(ref.bundle, { repo, tag: "", digest: "" }, "wrong-tag-hint", ref.digest)).rejects.toThrow(/does not match tag/);
    await expect(client.authenticateCode(ref.bundle, { repo, tag: "other-tag", digest: "" }, ref.tag, ref.digest)).rejects.toThrow(/does not match tag/);
    await expect(client.authenticateCode(ref.bundle, { repo, tag: "", digest: "1".repeat(64) }, ref.tag, ref.digest)).rejects.toThrow(/verifying bundle/);
    await expect(client.authenticateCode(ref.bundle, { repo: "tinfoilsh/other", tag: "", digest: "" }, ref.tag, ref.digest)).rejects.toThrow(/signing identity/);
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("ProvenanceClient.authenticatePlatformEndorsements"), () => {
  const run = async (fixture: ConformanceFixture, format = ARTIFACT_FORMAT) => {
    const doc = await documentOf(fixture);
    const ref = doc.sigstorePlatform();
    return (await clientOf(fixture)).authenticatePlatformEndorsements(ref.bundle, ref.repo, ref.tag, ref.digest, format);
  };

  for (const fixture of POLICY_VECTORS) {
    const { expected } = fixture;
    it(`${fixture.id}: ${expected.accepted ? "accepts" : "rejects"}`, async () => {
      if (!expected.accepted) {
        await expect(run(fixture)).rejects.toThrow();
        return;
      }
      const platform = await run(fixture);
      expect(platform.repo).toBe(PLATFORM_ENDORSEMENTS_REPO);
      expect(platform.tag).toMatch(/^platform-v/);
      expect(platform.artifact.format).toBe(ARTIFACT_FORMAT);
      expect(platform.artifact.policies.size).toBeGreaterThan(0);
      expect(platform.artifact.machines.size).toBeGreaterThan(0);
    });
  }

  it("requires the artifact format the flow selects, and the publishing repository", async () => {
    const fixture = loadFixture("policy/policy-happy.json");
    await expect(run(fixture, ARTIFACT_FORMAT_V2)).rejects.toThrow(/must use/);
    await expect(run(fixture, "https://tinfoil.sh/predicate/platform-endorsements/v9")).rejects.toThrow(/unsupported platform artifact format/);
    const doc = await documentOf(fixture);
    const ref = doc.sigstorePlatform();
    const client = await clientOf(fixture);
    await expect(client.authenticatePlatformEndorsements(ref.bundle, "tinfoilsh/other", ref.tag, ref.digest, ARTIFACT_FORMAT)).rejects.toThrow(
      /platform endorsements repo/,
    );
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("authenticateFreshness"), () => {
  /** What the code witness of each vector proves on its own; vectors absent here fail elsewhere in the flow. */
  const CODE_WITNESS: Readonly<Record<string, RegExp | "accept">> = {
    "fr1-nonce-fresh": "accept",
    "fr1-nonce-stale": "accept",
    "fr2-future-skew": /timestamp is in the future/,
    "fr2-mismatched-endorsement": /witness does not match authenticated artifact/,
    "fr2-missing-code-freshness": /collateral entry not found/,
    "fr2-missing-platform-freshness": "accept",
    "fr2-pos-at-max-age": "accept",
    "fr2-stale": /witness is stale/,
    "fr2-witness-garbage-payload": /parsing in-toto statement/,
    "fr2-witness-subject-mismatch": /statement subject does not match/,
    "fr2-witness-wrong-predicate": /unexpected freshness predicate format/,
    "fr2-witness-wrong-type": /unexpected freshness statement type/,
    "fr2-witness-zero-subject": /has no subject/,
    "fr2-wrong-identity": /signing identity/,
  };

  const witness = async (fixture: ConformanceFixture, maxAgeMs = 0): Promise<Date> => {
    const doc = await documentOf(fixture);
    const code = await authenticateCodeOf(fixture);
    return authenticateFreshness(await clientOf(fixture), doc.freshness("code-freshness").bundle, code, clockOf(fixture), maxAgeMs);
  };

  for (const fixture of FRESHNESS_VECTORS) {
    const verdict = CODE_WITNESS[fixture.id];
    it(`${fixture.id}: code witness ${verdict === "accept" ? "verifies" : "rejects"}`, async () => {
      expect(verdict, `no expected verdict for vector ${fixture.id}`).toBeDefined();
      if (verdict === "accept") {
        const at = await witness(fixture);
        expect(at.getTime()).toBeLessThanOrEqual(clockOf(fixture).getTime() + MAX_FRESHNESS_FUTURE_SKEW_MS);
      } else {
        await expect(witness(fixture)).rejects.toThrow(verdict);
      }
    });
  }

  it("applies the caller's maximum age, with zero selecting the default", async () => {
    const fixture = loadFixture("freshness/fr2-pos-at-max-age.json");
    const at = await witness(fixture, 0);
    const age = clockOf(fixture).getTime() - at.getTime();
    expect(age).toBeLessThanOrEqual(MAX_FRESHNESS_AGE_MS);
    await expect(witness(fixture, Math.max(1, age - 1000))).rejects.toThrow(/stale/);
    await expect(witness(fixture, -1)).rejects.toThrow(/finite, non-negative/);
    await expect(witness(fixture, Infinity)).rejects.toThrow(/finite, non-negative/);
    const doc = await documentOf(fixture);
    const code = await authenticateCodeOf(fixture);
    await expect(authenticateFreshness(await clientOf(fixture), doc.freshness("code-freshness").bundle, code, new Date(NaN), 0)).rejects.toThrow(/clock is invalid/);
  });

  it("verifies the golden document's code witness", async () => {
    await expect(witness(loadFixture("golden/golden-happy.json"))).resolves.toBeInstanceOf(Date);
  });

  /** The code witness bundle of a vector as plain JSON, for mutation. */
  const witnessWire = (fixture: ConformanceFixture): Record<string, any> => {
    const doc = JSON.parse(new TextDecoder().decode(inputBytes(fixture, "document_b64"))) as { collateral: { id: string; data: Record<string, any> }[] };
    const entry = doc.collateral.find((c) => c.id === "code-freshness");
    if (entry === undefined) throw new Error(`${fixture.id} has no code-freshness collateral`);
    return structuredClone(entry.data.sigstore_bundle) as Record<string, any>;
  };
  const toJson = (value: unknown): JsonValue => strictParse(utf8(JSON.stringify(value)));

  it("rejects a witness whose first log entry carries no inclusion promise", async () => {
    const fixture = loadFixture("freshness/fr1-nonce-fresh.json");
    const wire = witnessWire(fixture);
    delete wire.verificationMaterial.tlogEntries[0].inclusionPromise;
    const code = await authenticateCodeOf(fixture);
    // Bundle verification already demands a verified observer timestamp; the witness time check behind it would reject the same way.
    await expect(authenticateFreshness(await clientOf(fixture), toJson(wire), code, clockOf(fixture), 0)).rejects.toThrow(
      /no verified observer timestamp/i,
    );
  });

  describe("promisedLogTime", () => {
    let root: Awaited<ReturnType<typeof clientOf>>["root"];
    let entry: TlogEntry;
    beforeAll(async () => {
      const fixture = loadFixture("freshness/fr1-nonce-fresh.json");
      root = (await clientOf(fixture)).root;
      entry = parseBundle(toJson(witnessWire(fixture))).tlogEntries[0]!;
      expect(entry.inclusionPromise).toBeDefined();
    });

    it("returns the promised integration time of the vector's witness", async () => {
      await expect(promisedLogTime(root, [entry])).resolves.toEqual(new Date(Number(entry.integratedTime) * 1000));
    });

    it("is undefined without a promise or an integration time", async () => {
      await expect(promisedLogTime(root, [])).resolves.toBeUndefined();
      await expect(promisedLogTime(root, [{ ...entry, inclusionPromise: undefined }])).resolves.toBeUndefined();
      await expect(promisedLogTime(root, [{ ...entry, integratedTime: undefined }])).resolves.toBeUndefined();
    });

    it("rejects a promise that does not verify under the log key", async () => {
      const tampered = new Uint8Array(entry.inclusionPromise!);
      tampered[tampered.length - 1] ^= 0x01;
      await expect(promisedLogTime(root, [{ ...entry, inclusionPromise: tampered }])).rejects.toThrow(/inclusion promise does not verify/);
      // The promise signs over the integration time, the index and the body, so none can change.
      await expect(promisedLogTime(root, [{ ...entry, integratedTime: entry.integratedTime! + 1n }])).rejects.toThrow(/does not verify/);
      await expect(promisedLogTime(root, [{ ...entry, logIndex: entry.logIndex + 1n }])).rejects.toThrow(/does not verify/);
      const body = new Uint8Array(entry.canonicalizedBody);
      body[0] ^= 0x01;
      await expect(promisedLogTime(root, [{ ...entry, canonicalizedBody: body }])).rejects.toThrow(/does not verify/);
    });

    it("rejects a log the trusted root does not list and a time outside the log key's validity", async () => {
      await expect(promisedLogTime(root, [{ ...entry, logId: "00".repeat(32) }])).rejects.toThrow(/does not list/);
      const log = root.transparencyLogs.find((l) => l.logId === entry.logId)!;
      const before = BigInt(Math.floor(log.validFrom.getTime() / 1000)) - 1n;
      await expect(promisedLogTime(root, [{ ...entry, integratedTime: before }])).rejects.toThrow(/outside the log key's validity/);
    });
  });
});

describe("freshness statement checks", () => {
  const expected: AuthenticatedArtifact = { repo: "tinfoilsh/model", tag: "v1", commit: "a".repeat(40), subjectName: "model.tar", digest: "b".repeat(64) };
  const witness = { repo: "tinfoilsh/model", tag: "v1", commit: "a".repeat(40), subject: { name: "model.tar", digest: "sha256:" + "b".repeat(64) } };

  it("binds every witness field to the artifact", () => {
    expect(() => validateWitness(witness, expected)).not.toThrow();
    expect(() => validateWitness({ ...witness, repo: "tinfoilsh/other" }, expected)).toThrow(/does not match/);
    expect(() => validateWitness({ ...witness, tag: "v2" }, expected)).toThrow(/does not match/);
    expect(() => validateWitness({ ...witness, commit: "c".repeat(40) }, expected)).toThrow(/does not match/);
    expect(() => validateWitness({ ...witness, subject: { ...witness.subject, name: "other" } }, expected)).toThrow(/does not match/);
    expect(() => validateWitness({ ...witness, subject: { ...witness.subject, digest: "b".repeat(64) } }, expected)).toThrow(/does not match/);
  });

  it("judges the log time against the clock", () => {
    const now = new Date("2025-06-01T00:00:00Z");
    expect(validateFreshnessTime(new Date(now.getTime() - MAX_FRESHNESS_AGE_MS), now, MAX_FRESHNESS_AGE_MS)).toEqual(new Date(now.getTime() - MAX_FRESHNESS_AGE_MS));
    expect(() => validateFreshnessTime(new Date(now.getTime() - MAX_FRESHNESS_AGE_MS - 1), now, MAX_FRESHNESS_AGE_MS)).toThrow(/stale/);
    expect(() => validateFreshnessTime(new Date(now.getTime() + MAX_FRESHNESS_FUTURE_SKEW_MS + 1), now, MAX_FRESHNESS_AGE_MS)).toThrow(/future/);
    expect(() => validateFreshnessTime(undefined, now, MAX_FRESHNESS_AGE_MS)).toThrow(/no verified transparency-log timestamp/);
    expect(() => validateFreshnessTime(now, new Date(NaN), MAX_FRESHNESS_AGE_MS)).toThrow(/clock or maximum age is invalid/);
    expect(() => validateFreshnessTime(now, now, Infinity)).toThrow(/clock or maximum age is invalid/);
    expect(() => validateFreshnessTime(now, now, -1)).toThrow(/clock or maximum age is invalid/);
    expect(() => validateFreshnessTime(new Date(NaN), now, MAX_FRESHNESS_AGE_MS)).toThrow(/no verified transparency-log timestamp/);
  });

  it("decodes the statement strictly", () => {
    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "model.tar", digest: { sha256: "b".repeat(64) } }],
      predicateType: FRESHNESS_PREDICATE_FORMAT,
      predicate: { format: FRESHNESS_PREDICATE_FORMAT, endorses: witness },
    };
    const parsed = parseFreshnessStatement(utf8(JSON.stringify(statement)));
    expect(parsed.endorses).toEqual(witness);
    expect(parsed.subjects).toEqual([{ name: "model.tar", sha256: "b".repeat(64) }]);
    expect(() => parseFreshnessStatement(utf8(JSON.stringify({ ...statement, extra: 1 })))).toThrow(/unknown object member/);
    expect(() => parseFreshnessStatement(utf8(JSON.stringify({ ...statement, predicate: { ...statement.predicate, note: 1 } })))).toThrow(/unknown object member/);
    // A null subject reads as an empty one; a non-object subject rejects.
    expect(parseFreshnessStatement(utf8(JSON.stringify({ ...statement, subject: [null] }))).subjects).toEqual([{ name: "", sha256: "" }]);
    expect(() => parseFreshnessStatement(utf8(JSON.stringify({ ...statement, subject: [1] })))).toThrow(/parsing freshness statement/);
    expect(() => parseFreshnessStatement(utf8("not json"))).toThrow(/parsing freshness statement/);
  });
});

// ---------------------------------------------------------------- signed predicate

describe("signedPredicate", () => {
  it("returns the predicate member as signed, with number literals and member order intact", () => {
    const payload = utf8('{"_type":"t","subject":[],"predicateType":"p","predicate":{"z":18446744073709551615,"a":1.50,"n":{"k":[1,2.0e3]}}}');
    const { predicateType, predicate } = signedPredicate(payload);
    expect(predicateType).toBe("p");
    expect(new TextDecoder().decode(predicate)).toBe('{"z":18446744073709551615,"a":1.50,"n":{"k":[1,2.0e3]}}');
    expect(() => signedPredicate(utf8('{"predicate":[]}'))).toThrow(/predicate is not an object/);
    expect(() => signedPredicate(utf8('{"predicate":null}'))).toThrow(/predicate is not an object/);
    expect(() => signedPredicate(utf8('{"predicate":{},"other":1}'))).toThrow(/unknown object member/);
    expect(() => signedPredicate(utf8('{"predicate":{"a":1,"a":2}}'))).toThrow();
    expect(strictParse(predicate)).toBeInstanceOf(Map);
  });
});

// ---------------------------------------------------------------- runtime

describe("authenticateRuntime", () => {
  const pin = { repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: "a".repeat(64) };
  const client = { verifyBundle: () => Promise.reject(new Error("must not be reached")) } as unknown as ProvenanceClient;
  let fixtureClient: ProvenanceClient;
  beforeAll(async () => {
    fixtureClient = withoutVectors ? client : await ProvenanceClient.default();
  });

  it("rejects collateral that does not match the pin before verifying anything", async () => {
    const material = { ...pin, tag: "v1.2.4", manifest: utf8("{}"), bundle: new Map() };
    await expect(authenticateRuntime(client, material, pin)).rejects.toThrow(/does not match the endorsed config's runtime pin/);
  });

  it("rejects a manifest whose digest is not the pin before verifying the bundle", async () => {
    const material = { ...pin, manifest: utf8('{"version":"v1.2.3"}'), bundle: new Map() };
    await expect(authenticateRuntime(fixtureClient, material, pin)).rejects.toThrow(/manifest does not match the config's digest pin/);
  });
});
