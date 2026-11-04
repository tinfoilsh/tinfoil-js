/**
 * Tests for the key-signed approvals (approval.ts): config endorsements and
 * artifact-freshness statements. Bundles are minted with helpers/keyed.ts
 * (a fresh signing key and a transparency log) and their inner timestamps
 * with helpers/tsa.ts (a synthetic timestamp authority listed in the same
 * trusted root), so every rule is exercised end to end without any fixture.
 */
import { createHash, createPublicKey } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { sha256, toHex, utf8 } from "../../src/v3/internal/bytes.js";
import {
  ARTIFACT_FRESHNESS_PREDICATE_TYPE,
  CONFIG_ENDORSEMENT_PREDICATE_TYPE,
  CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2,
  ConfigVerifier,
  FreshnessVerifier,
  IN_TOTO_STATEMENT_V1,
  isRuntimeArtifactName,
  KIND_PLATFORM,
  KIND_RUNTIME,
  MAX_CONFIG_SIZE,
  parseArtifactFreshnessStatement,
  parseConfigName,
  parseConfigStatement,
  PLATFORM_ARTIFACT_NAME,
  PUBLIC_SCOPE,
  publicSigningKeys,
  runtimeArtifactName,
  SCOPE_PREFIX,
  validateConfigIdentity,
  validateConfigPins,
  validateFreshnessArtifact,
  validateRevision,
  validateScope,
  type ConfigPolicy,
  type FreshnessArtifact,
  type FreshnessPolicy,
} from "../../src/v3/internal/endorsement/approval.js";
import { DEFAULT_FUTURE_SKEW_MS, DEFAULT_MAX_AGE_MS } from "../../src/v3/internal/endorsement/time.js";
import { pinnedKeys, type PinnedKey } from "../../src/v3/internal/sigstore/keyed.js";
import { endorsementReference, timestampInput, verifyTimestamp } from "../../src/v3/internal/sigstore/timestamp.js";
import type { TrustedRoot } from "../../src/v3/internal/sigstore/trusted-root.js";
import { PUBLIC_SIGNING_KEY_PEM } from "../../src/v3/trust/signing-keys.js";
import { b64, build, newLog, newSigner, rootOf, toJson, type Signer, type TestLog } from "./helpers/keyed.js";
import { authorityJson, newTimestampAuthority, timestampResponse, type TimestampAuthority } from "./helpers/tsa.js";

const CONFIG_DOMAIN = "tinfoil-config-freshness/v1\0";
const CONFIG_DOMAIN_V2 = "tinfoil-config-freshness/v2\0";
const ARTIFACT_DOMAIN = "tinfoil-artifact-freshness/v1\0";

const NOW = new Date("2025-06-15T12:00:00Z");
const GEN_TIME = new Date("2025-06-15T11:00:00Z");
const RUNTIME_DIGEST = "a".repeat(64);
const V2_CONFIG = utf8(`name: app\ncvm-version: v1.2.3@sha256:${RUNTIME_DIGEST}\n`);
const V1_CONFIG = utf8("name: app\nreplicas: 2\n");

let signer: Signer;
let other: Signer;
let log: TestLog;
let tsa: TimestampAuthority;
let root: TrustedRoot;
let keys: PinnedKey[];

beforeAll(async () => {
  signer = await newSigner();
  other = await newSigner();
  log = await newLog("ecdsa");
  tsa = await newTimestampAuthority();
  root = await rootOf([log], [authorityJson(tsa)]);
  keys = await pinnedKeys([signer.pem]);
});

const hex = async (bytes: Uint8Array): Promise<string> => toHex(await sha256(bytes));

interface ConfigOptions {
  readonly name?: string;
  readonly config?: Uint8Array;
  readonly v2?: boolean;
  readonly scope?: string;
  readonly runtime?: { repo: string; tag: string; digest: string };
  readonly genTime?: Date;
  readonly signer?: Signer;
  /** Rewrites the statement after its timestamp was minted. */
  readonly tamper?: (statement: any) => void;
  readonly timestampDomain?: string;
}

/** A config endorsement bundle whose inner timestamp covers the statement's core. */
async function configBundle(opts: ConfigOptions = {}): Promise<{ json: unknown; payload: Uint8Array; config: Uint8Array }> {
  const v2 = opts.v2 ?? false;
  const config = opts.config ?? (v2 ? V2_CONFIG : V1_CONFIG);
  const predicate: Record<string, unknown> = {};
  if (v2) {
    predicate.scope = opts.scope ?? PUBLIC_SCOPE;
    predicate.runtime = opts.runtime ?? { repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: RUNTIME_DIGEST };
  }
  const core = {
    _type: IN_TOTO_STATEMENT_V1,
    subject: [{ name: opts.name ?? "/acme/app/v7", digest: { sha256: await hex(config) } }],
    predicateType: v2 ? CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2 : CONFIG_ENDORSEMENT_PREDICATE_TYPE,
    predicate,
  };
  const domain = opts.timestampDomain ?? (v2 ? CONFIG_DOMAIN_V2 : CONFIG_DOMAIN);
  const response = await timestampResponse(tsa, timestampInput(domain, toJson(core)), opts.genTime ?? GEN_TIME);
  const statement = { ...core, predicate: { ...predicate, freshness: { rfc3161Timestamp: b64(response) } } };
  opts.tamper?.(statement);
  const built = await build(opts.signer ?? signer, log, { statement });
  return { json: built.json, payload: built.payload, config };
}

const policy = (overrides: Partial<ConfigPolicy> = {}): ConfigPolicy => ({
  identity: "",
  revision: "",
  digest: "",
  now: NOW,
  maxAgeMs: 0,
  futureSkewMs: 0,
  ...overrides,
});

describe("timestamp authority helper", () => {
  it("mints responses the verifier accepts under its root, and rejects a foreign policy", async () => {
    const input = utf8("some input");
    expect(await verifyTimestamp(root, await timestampResponse(tsa, input, GEN_TIME), input)).toEqual(GEN_TIME);
    await expect(verifyTimestamp(root, await timestampResponse(tsa, input, GEN_TIME, { policy: "1.2.3" }), input)).rejects.toThrow(/policy/);
    await expect(verifyTimestamp(root, await timestampResponse(tsa, input, GEN_TIME), utf8("other"))).rejects.toThrow(/does not match/);
  });
});

describe("config names and scopes", () => {
  it("parses /org/project/revision names", () => {
    expect(parseConfigName("/acme/app/v7")).toEqual({ identity: "/acme/app", revision: "v7" });
    expect(parseConfigName("/a-b/c0/1.2_3-x")).toEqual({ identity: "/a-b/c0", revision: "1.2_3-x" });
    for (const bad of ["acme/app/v7", "/acme/v7", "/acme/app/", "/Acme/app/v7", "/acme/app/-v7", "/acme/app/v7\0", "/acme/app/v7/x", "/a--b/app/v7"]) {
      expect(() => parseConfigName(bad), bad).toThrow();
    }
    expect(() => parseConfigName("/acme/app/" + "r".repeat(129))).toThrow(/revision/);
    expect(() => validateConfigIdentity("/" + "a".repeat(64) + "/app")).toThrow(/component/);
    expect(() => validateRevision("")).toThrow(/revision/);
  });

  it("accepts the public scope and canonical hex scope ids only", () => {
    expect(() => validateScope(PUBLIC_SCOPE)).not.toThrow();
    expect(() => validateScope(SCOPE_PREFIX + "0".repeat(32))).not.toThrow();
    expect(() => validateScope(SCOPE_PREFIX + "A".repeat(32))).toThrow(/scope/);
    expect(() => validateScope(SCOPE_PREFIX + "0".repeat(31))).toThrow(/scope/);
    expect(() => validateScope("https://example.com/scopes/public")).toThrow(/scope/);
  });

  it("validates pins independently of the clock", () => {
    expect(() => validateConfigPins(policy())).not.toThrow();
    expect(() => validateConfigPins(policy({ identity: "/acme/app", revision: "v7", digest: "0".repeat(64) }))).not.toThrow();
    expect(() => validateConfigPins(policy({ identity: "acme/app" }))).toThrow(/identity/);
    expect(() => validateConfigPins(policy({ revision: "-x" }))).toThrow(/revision/);
    expect(() => validateConfigPins(policy({ digest: "A".repeat(64) }))).toThrow(/lowercase SHA-256/);
  });
});

describe("config statements", () => {
  it("decodes v1 and v2 statements strictly", async () => {
    const v1 = parseConfigStatement((await configBundle()).payload);
    expect(v1.predicateType).toBe(CONFIG_ENDORSEMENT_PREDICATE_TYPE);
    expect(v1.scope).toBe("");
    expect(v1.runtime).toBeUndefined();
    expect(v1.timestamp.length).toBeGreaterThan(0);
    const v2 = parseConfigStatement((await configBundle({ v2: true })).payload);
    expect(v2.scope).toBe(PUBLIC_SCOPE);
    expect(v2.runtime).toEqual({ repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: RUNTIME_DIGEST });
  });

  it.each<[string, (s: any) => void, RegExp]>([
    ["an unknown member", (s) => (s.extra = 1), /unknown object member/],
    ["an unknown predicate member", (s) => (s.predicate.note = 1), /unknown object member/],
    ["a wrong statement type", (s) => (s._type = "https://in-toto.io/Statement/v0.1"), /unsupported config endorsement statement type/],
    ["a wrong predicate type", (s) => (s.predicateType = ARTIFACT_FRESHNESS_PREDICATE_TYPE), /unsupported config endorsement statement type/],
    ["two subjects", (s) => s.subject.push(s.subject[0]), /exactly one subject/],
    ["a second digest", (s) => (s.subject[0].digest.sha512 = "x"), /one lowercase SHA-256 digest/],
    ["an uppercase digest", (s) => (s.subject[0].digest.sha256 = s.subject[0].digest.sha256.toUpperCase()), /one lowercase SHA-256 digest/],
    ["a name without a revision", (s) => (s.subject[0].name = "acme"), /no revision/],
    ["a runtime on a v1 statement", (s) => (s.predicate.runtime = { repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: RUNTIME_DIGEST }), /v1 config endorsement cannot/],
    ["a scope on a v1 statement", (s) => (s.predicate.scope = PUBLIC_SCOPE), /v1 config endorsement cannot/],
    ["no inner timestamp", (s) => delete s.predicate.freshness, /requires an inner timestamp/],
    ["an empty inner timestamp", (s) => (s.predicate.freshness.rfc3161Timestamp = ""), /requires an inner timestamp/],
    ["a null freshness", (s) => (s.predicate.freshness = null), /requires an inner timestamp/],
  ])("rejects %s", async (_what, tamper, pattern) => {
    const { payload } = await configBundle({ tamper });
    expect(() => parseConfigStatement(payload)).toThrow(pattern);
  });

  it("rejects a v2 statement without a scope or runtime, or with an invalid one", async () => {
    const cases: [ConfigOptions, RegExp][] = [
      [{ v2: true, tamper: (s) => delete s.predicate.runtime }, /requires a runtime reference/],
      [{ v2: true, tamper: (s) => delete s.predicate.scope }, /scope/],
      [{ v2: true, runtime: { repo: "other/repo", tag: "v1.2.3", digest: RUNTIME_DIGEST } }, /runtime repository/],
      [{ v2: true, runtime: { repo: "tinfoilsh/cvmimage", tag: "v1.2", digest: RUNTIME_DIGEST } }, /full semantic version/],
    ];
    for (const [opts, pattern] of cases) {
      const { payload } = await configBundle(opts);
      expect(() => parseConfigStatement(payload)).toThrow(pattern);
    }
  });

  it("bounds the statement size", () => {
    expect(() => parseConfigStatement(new Uint8Array())).toThrow(/size/);
    expect(() => parseConfigStatement(new Uint8Array((128 << 10) + 1))).toThrow(/size/);
  });
});

describe("ConfigVerifier", () => {
  it("requires a root with transparency logs and at least one key", async () => {
    expect(() => new ConfigVerifier(root, [])).toThrow(/at least one/);
    const logless = await rootOf([], [authorityJson(tsa)]);
    expect(() => new ConfigVerifier(logless, keys)).toThrow(/Rekor trust/);
    expect(() => new FreshnessVerifier(root, [])).toThrow(/at least one/);
  });

  it("verifies a v1 approval and reports its identity, hint, reference and approval time", async () => {
    const { json, payload, config } = await configBundle();
    const verified = await new ConfigVerifier(root, keys).verify(config, toJson(json), policy({ identity: "/acme/app", revision: "v7" }));
    expect(verified.name).toBe("/acme/app/v7");
    expect(verified.digest).toBe(await hex(config));
    expect(verified.signingKeyHint).toBe(signer.hint);
    expect(verified.approvalTime).toEqual(GEN_TIME);
    expect(verified.reference).toBe(await endorsementReference(payload));
    expect(verified.scope).toBe("");
    expect(verified.runtime).toBeUndefined();
  });

  it("verifies a v2 approval, binds the endorsed runtime to the config, and verifies the digest alone", async () => {
    const { json, config } = await configBundle({ v2: true });
    const verifier = new ConfigVerifier(root, keys);
    const verified = await verifier.verify(config, toJson(json), policy({ digest: await hex(config) }));
    expect(verified.runtime).toEqual({ repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: RUNTIME_DIGEST });
    expect(verified.scope).toBe(PUBLIC_SCOPE);
    // Without the config bytes, a v2 statement still pins the digest and runtime.
    expect((await verifier.verify(undefined, toJson(json), policy())).digest).toBe(await hex(config));
    // The config's own pin must equal the endorsed runtime.
    const drift = await configBundle({ v2: true, runtime: { repo: "tinfoilsh/cvmimage", tag: "v1.2.4", digest: RUNTIME_DIGEST } });
    await expect(verifier.verify(drift.config, toJson(drift.json), policy())).rejects.toThrow(/config runtime does not match/);
    // A v1 statement cannot be verified without the config.
    const v1 = await configBundle();
    await expect(verifier.verify(undefined, toJson(v1.json), policy())).rejects.toThrow(/requires a v2 config endorsement/);
  });

  it("enforces the identity, revision and digest pins and the config bytes", async () => {
    const { json, config } = await configBundle();
    const verifier = new ConfigVerifier(root, keys);
    await expect(verifier.verify(config, toJson(json), policy({ identity: "/acme/other" }))).rejects.toThrow(/pinned identity or revision/);
    await expect(verifier.verify(config, toJson(json), policy({ revision: "v8" }))).rejects.toThrow(/pinned identity or revision/);
    await expect(verifier.verify(config, toJson(json), policy({ digest: "0".repeat(64) }))).rejects.toThrow(/pinned digest/);
    await expect(verifier.verify(utf8("other config"), toJson(json), policy())).rejects.toThrow(/config bytes do not match/);
    await expect(verifier.verify(new Uint8Array(), toJson(json), policy())).rejects.toThrow(/config size/);
    await expect(verifier.verify(new Uint8Array(MAX_CONFIG_SIZE + 1), toJson(json), policy())).rejects.toThrow(/config size/);
    await expect(verifier.verify(config, toJson(json), policy({ identity: "bad" }))).rejects.toThrow(/identity/);
  });

  it("rejects a signature by a key that is not pinned", async () => {
    const { json, config } = await configBundle({ signer: other });
    await expect(new ConfigVerifier(root, keys).verify(config, toJson(json), policy())).rejects.toThrow(/untrusted approval signing key/);
    const rotated = new ConfigVerifier(root, await pinnedKeys([signer.pem, other.pem]));
    expect((await rotated.verify(config, toJson(json), policy())).signingKeyHint).toBe(other.hint);
  });

  it("judges the approval by its inner timestamp against the policy window", async () => {
    const verifier = new ConfigVerifier(root, keys);
    const atEdge = await configBundle({ genTime: new Date(NOW.getTime() - DEFAULT_MAX_AGE_MS) });
    expect((await verifier.verify(atEdge.config, toJson(atEdge.json), policy())).approvalTime).toEqual(new Date(NOW.getTime() - DEFAULT_MAX_AGE_MS));
    const stale = await configBundle({ genTime: new Date(NOW.getTime() - DEFAULT_MAX_AGE_MS - 1000) });
    await expect(verifier.verify(stale.config, toJson(stale.json), policy())).rejects.toThrow(/inner timestamp: .*outside the accepted window/);
    const future = await configBundle({ genTime: new Date(NOW.getTime() + DEFAULT_FUTURE_SKEW_MS + 1000) });
    await expect(verifier.verify(future.config, toJson(future.json), policy())).rejects.toThrow(/inner timestamp: .*outside the accepted window/);
    const custom = await configBundle({ genTime: new Date(NOW.getTime() - 3600_000) });
    await expect(verifier.verify(custom.config, toJson(custom.json), policy({ maxAgeMs: 1800_000 }))).rejects.toThrow(/outside the accepted window/);
  });

  it("binds the inner timestamp to the whole statement core", async () => {
    const verifier = new ConfigVerifier(root, keys);
    // A timestamp minted over a v1 core does not verify a statement whose core differs.
    const wrongDomain = await configBundle({ timestampDomain: CONFIG_DOMAIN_V2 });
    await expect(verifier.verify(wrongDomain.config, toJson(wrongDomain.json), policy())).rejects.toThrow(/inner timestamp: .*does not match the input/);
    const retargeted = await configBundle({ v2: true, tamper: (s) => (s.predicate.scope = SCOPE_PREFIX + "0".repeat(32)) });
    await expect(verifier.verify(retargeted.config, toJson(retargeted.json), policy())).rejects.toThrow(/inner timestamp: .*does not match the input/);
  });

  it("requires the timestamp authority to be trusted", async () => {
    const { json, config } = await configBundle();
    const untrusting = await rootOf([log], [authorityJson(await newTimestampAuthority())]);
    await expect(new ConfigVerifier(untrusting, keys).verify(config, toJson(json), policy())).rejects.toThrow(/inner timestamp: no trusted timestamp authority/);
  });
});

describe("artifact freshness", () => {
  const platform: FreshnessArtifact = { kind: KIND_PLATFORM, repo: "tinfoilsh/cvmimage", tag: "platform-v2.0.0", name: PLATFORM_ARTIFACT_NAME, digest: "b".repeat(64) };
  const runtime: FreshnessArtifact = { kind: KIND_RUNTIME, repo: "tinfoilsh/cvmimage", tag: "v1.2.3", name: runtimeArtifactName("v1.2.3"), digest: "c".repeat(64) };

  it("validates artifacts", () => {
    expect(() => validateFreshnessArtifact(platform)).not.toThrow();
    expect(() => validateFreshnessArtifact(runtime)).not.toThrow();
    expect(() => validateFreshnessArtifact({ ...runtime, name: runtimeArtifactName("v1.2.3+build.7") })).not.toThrow();
    expect(() => validateFreshnessArtifact({ ...platform, tag: "v2.0.0" })).toThrow(/platform freshness/);
    expect(() => validateFreshnessArtifact({ ...platform, repo: "tinfoilsh/other" })).toThrow(/platform freshness/);
    expect(() => validateFreshnessArtifact({ ...platform, name: "x.json" })).toThrow(/platform freshness/);
    expect(() => validateFreshnessArtifact({ ...platform, tag: "platform-v2.0" })).toThrow(/canonical semantic version/);
    expect(() => validateFreshnessArtifact({ ...platform, tag: "platform-v2.0.0+meta" })).toThrow(/canonical semantic version/);
    expect(() => validateFreshnessArtifact({ ...runtime, name: runtimeArtifactName("v1.2.4") })).toThrow(/runtime freshness/);
    expect(() => validateFreshnessArtifact({ ...runtime, tag: "v1.2" })).toThrow(/runtime freshness/);
    expect(() => validateFreshnessArtifact({ ...runtime, digest: "C".repeat(64) })).toThrow(/lowercase hex/);
    expect(() => validateFreshnessArtifact({ ...runtime, kind: "image" as never })).toThrow(/unsupported freshness artifact kind/);
  });

  it("recognizes versioned runtime manifest names", () => {
    expect(isRuntimeArtifactName("v1.2.3", "tinfoil-inference-v1.2.3-manifest.json")).toBe(true);
    expect(isRuntimeArtifactName("v1.2.3", "tinfoil-inference-v1.2.3+build-manifest.json")).toBe(true);
    expect(isRuntimeArtifactName("v1.2.3", "tinfoil-inference-v1.2.4-manifest.json")).toBe(false);
    expect(isRuntimeArtifactName("v1.2.3", "tinfoil-inference-v1.2.3-manifest.yaml")).toBe(false);
    expect(isRuntimeArtifactName("v1.2.3", "x-tinfoil-inference-v1.2.3-manifest.json")).toBe(false);
  });

  interface ArtifactOptions {
    readonly artifact?: FreshnessArtifact;
    readonly genTime?: Date;
    readonly signer?: Signer;
    readonly tamper?: (statement: any) => void;
  }

  async function freshnessBundle(opts: ArtifactOptions = {}): Promise<{ json: unknown; payload: Uint8Array }> {
    const a = opts.artifact ?? platform;
    const core = {
      _type: IN_TOTO_STATEMENT_V1,
      subject: [{ name: a.name, digest: { sha256: a.digest } }],
      predicateType: ARTIFACT_FRESHNESS_PREDICATE_TYPE,
      predicate: { kind: a.kind, repo: a.repo, tag: a.tag },
    };
    const response = await timestampResponse(tsa, timestampInput(ARTIFACT_DOMAIN, toJson(core)), opts.genTime ?? GEN_TIME);
    const statement = { ...core, predicate: { ...core.predicate, freshness: { rfc3161Timestamp: b64(response) } } };
    opts.tamper?.(statement);
    const built = await build(opts.signer ?? signer, log, { statement });
    return { json: built.json, payload: built.payload };
  }

  const freshnessPolicy = (artifact: FreshnessArtifact, overrides: Partial<FreshnessPolicy> = {}): FreshnessPolicy => ({
    artifact,
    now: NOW,
    maxAgeMs: 0,
    futureSkewMs: 0,
    ...overrides,
  });

  it("decodes statements strictly", async () => {
    const s = parseArtifactFreshnessStatement((await freshnessBundle()).payload);
    expect(s.artifact).toEqual(platform);
    for (const [what, tamper, pattern] of [
      ["an unknown member", (st: any) => (st.predicate.extra = 1), /unknown object member/],
      ["a wrong predicate type", (st: any) => (st.predicateType = CONFIG_ENDORSEMENT_PREDICATE_TYPE), /unsupported artifact freshness statement/],
      ["two subjects", (st: any) => st.subject.push(st.subject[0]), /unsupported artifact freshness statement/],
      ["an unknown kind", (st: any) => (st.predicate.kind = "image"), /unsupported freshness artifact kind/],
      ["no inner timestamp", (st: any) => delete st.predicate.freshness, /requires an inner timestamp/],
    ] as const) {
      const { payload } = await freshnessBundle({ tamper });
      expect(() => parseArtifactFreshnessStatement(payload), what).toThrow(pattern);
    }
  });

  it("verifies platform and runtime approvals", async () => {
    const verifier = new FreshnessVerifier(root, keys);
    const p = await freshnessBundle();
    const verifiedPlatform = await verifier.verify(toJson(p.json), freshnessPolicy(platform));
    expect(verifiedPlatform).toEqual({ ...platform, reference: await endorsementReference(p.payload), signingKeyHint: signer.hint, approvalTime: GEN_TIME });
    const r = await freshnessBundle({ artifact: runtime });
    expect((await verifier.verify(toJson(r.json), freshnessPolicy(runtime))).name).toBe(runtime.name);
  });

  it("requires the approval to name exactly the expected artifact", async () => {
    const verifier = new FreshnessVerifier(root, keys);
    const { json } = await freshnessBundle();
    for (const changed of [
      { ...platform, digest: "d".repeat(64) },
      { ...platform, tag: "platform-v2.0.1" },
      { ...runtime },
    ]) {
      await expect(verifier.verify(toJson(json), freshnessPolicy(changed))).rejects.toThrow(/does not match the expected artifact/);
    }
    await expect(verifier.verify(toJson(json), freshnessPolicy({ ...platform, tag: "v2.0.0" }))).rejects.toThrow(/platform freshness/);
  });

  it("rejects an unpinned key, a stale timestamp, and a timestamp over a different core", async () => {
    const verifier = new FreshnessVerifier(root, keys);
    const foreign = await freshnessBundle({ signer: other });
    await expect(verifier.verify(toJson(foreign.json), freshnessPolicy(platform))).rejects.toThrow(/untrusted approval signing key/);
    const stale = await freshnessBundle({ genTime: new Date(NOW.getTime() - DEFAULT_MAX_AGE_MS - 1000) });
    await expect(verifier.verify(toJson(stale.json), freshnessPolicy(platform))).rejects.toThrow(/inner timestamp: .*outside the accepted window/);
    // The timestamp was minted for v2.0.0; the expected artifact and statement say v2.0.1.
    const moved = await freshnessBundle({ tamper: (s) => (s.predicate.tag = "platform-v2.0.1") });
    await expect(verifier.verify(toJson(moved.json), freshnessPolicy({ ...platform, tag: "platform-v2.0.1" }))).rejects.toThrow(
      /inner timestamp: .*does not match the input/,
    );
  });
});

describe("publicSigningKeys", () => {
  it("pins exactly the embedded key", async () => {
    const [key, ...rest] = await publicSigningKeys();
    expect(rest).toHaveLength(0);
    const der = new Uint8Array(createPublicKey(PUBLIC_SIGNING_KEY_PEM).export({ type: "spki", format: "der" }));
    expect(key!.hint).toBe(createHash("sha256").update(der).digest("base64"));
  });
});
