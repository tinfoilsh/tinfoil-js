/**
 * Provenance of the code and platform releases: certificate-signed Sigstore
 * bundles from the releasing repository's GitHub Actions workflow.
 *
 * A bundle verifies under the trusted root with the signing-identity policy
 * (SAN pattern, GitHub OIDC issuer, GitHub-hosted runner); the release
 * identity (tag, commit, subject) is then read from the certificate's
 * source-repository claims and the statement, and the predicate is decoded
 * from the signed payload bytes.
 */
import type { JsonValue } from "../json/index.js";
import { num, object, str } from "../json/decode.js";
import { serialize, strictParse, type JsonObject } from "../json/index.js";
import { parseRegister, type ExpectedSevSnp, type ExpectedTdx } from "../../measurement.js";
import { ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, parse as parseArtifact, type Artifact } from "../policy/artifact.js";
import type { Shape } from "../policy/shape.js";
import { parseBundle, type Bundle } from "../sigstore/bundle.js";
import { statementSubjects, verifyCertificateBundle, workflowIdentityPattern, type SigningIdentity, type Subject } from "../sigstore/certificate.js";
import { embeddedTrustedRoot, parseTrustedRoot, type TrustedRoot } from "../sigstore/trusted-root.js";
import { RUNTIME_REPO } from "../../document/collateral/runtime.js";
import {
  FRESHNESS_WITNESS_REPO,
  GIT_COMMIT_RE,
  REPO_NAME_RE,
  RUNTIME_REPO_ID,
  TINFOIL_ORGANIZATION_ID,
  type AuthenticatedArtifact,
  type Reference,
} from "./reference.js";

/** Predicate type of a release's multi-platform code measurement. */
export const MULTI_PLATFORM_PREDICATE_TYPE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";
/** The repository that publishes platform endorsements. */
export const PLATFORM_ENDORSEMENTS_REPO = "tinfoilsh/cvmimage";

/**
 * The only signing identity accepted for the platform-endorsements artifact:
 * the tag-triggered platform-release workflow of the publishing repository.
 */
export const PLATFORM_ENDORSEMENTS_IDENTITY = workflowIdentityPattern(PLATFORM_ENDORSEMENTS_REPO, "platform-release\\.yml", "refs/tags/platform-v[0-9][^@]*");
/** The freshness-witness workflow, run from its main branch. */
export const FRESHNESS_WITNESS_IDENTITY = workflowIdentityPattern(FRESHNESS_WITNESS_REPO, "freshness\\.yml", "refs/heads/main");

const TAG_REF_PREFIX = "refs/tags/";

/** Authenticated code provenance: the registers the release fixes on each platform, and its VM shape. */
export interface Code extends AuthenticatedArtifact {
  readonly sevSnp: ExpectedSevSnp;
  readonly tdx: ExpectedTdx;
  readonly shape: Shape;
}

/** The authenticated platform-endorsements artifact. */
export interface PlatformEndorsements extends AuthenticatedArtifact {
  readonly artifact: Artifact;
}

/** What a verified release bundle proved: the signer's identity, its signed payload, and the payload's subjects. */
export interface VerifiedRelease {
  readonly bundle: Bundle;
  readonly identity: SigningIdentity;
  readonly payload: Uint8Array;
  readonly subjects: readonly Subject[];
}

/**
 * The SAN pattern accepted for artifacts signed from `repo`: one workflow
 * file directly under the repository's .github/workflows directory, run
 * from a tag ref. The repository name is validated and escaped so it cannot
 * alter the pattern.
 */
export function signingIdentity(repo: string): RegExp {
  if (!REPO_NAME_RE.test(repo)) throw new Error(`invalid repository name ${JSON.stringify(repo)}`);
  return workflowIdentityPattern(repo, "[^/@]+", "refs/tags/[^@]+");
}

/** Authenticates provenance bundles against one trusted root. */
export class ProvenanceClient {
  /** @internal */
  constructor(readonly root: TrustedRoot) {}

  /** A client on the embedded production trusted root. */
  static async default(): Promise<ProvenanceClient> {
    return new ProvenanceClient(await embeddedTrustedRoot());
  }

  /** A client on the given trusted-root JSON. */
  static async fromJSON(trustedRootJSON: Uint8Array): Promise<ProvenanceClient> {
    let root: TrustedRoot;
    try {
      root = await parseTrustedRoot(trustedRootJSON);
    } catch (err) {
      throw new Error(`parsing trust root: ${message(err)}`);
    }
    return new ProvenanceClient(root);
  }

  /**
   * Verifies a bundle under `sanPattern` and the subject rule (subject 0
   * carries `hexDigest`, or the subject named `subjectName` does, exactly
   * once), and returns what it proved.
   */
  async verifyBundle(bundleJson: JsonValue, sanPattern: RegExp, hexDigest: string, subjectName?: string): Promise<VerifiedRelease> {
    const bundle = parseBundle(bundleJson);
    const verified = await verifyCertificateBundle(this.root, bundle, sanPattern, hexDigest, subjectName);
    return { bundle, identity: verified.identity, payload: verified.payload, subjects: statementSubjects(verified.payload) };
  }

  /**
   * Verifies code provenance: a bundle signed by a tag-ref workflow of
   * `ref.repo`, whose statement carries `digest` and the multi-platform
   * predicate. Pins in `ref` override the `tag` and `digest` hints.
   */
  async authenticateCode(bundle: JsonValue, ref: Reference, tag: string, hexDigest: string): Promise<Code> {
    const repo = ref.repo;
    tag = ref.tag || tag;
    hexDigest = ref.digest || hexDigest;
    let verified: VerifiedRelease;
    try {
      verified = await this.verifyBundle(bundle, signingIdentity(repo), hexDigest);
    } catch (err) {
      throw new Error(`verifying bundle: ${message(err)}`);
    }
    let measurements: { sevSnp: ExpectedSevSnp; tdx: ExpectedTdx; shape: Shape };
    try {
      measurements = codePredicate(verified.payload);
    } catch (err) {
      throw new Error(`code predicate: ${message(err)}`);
    }
    const authenticated = authenticatedArtifact(verified, repo, tag, hexDigest, "code");
    return { ...authenticated, ...measurements };
  }

  /**
   * Verifies the platform-endorsements artifact: `repo` must equal
   * PLATFORM_ENDORSEMENTS_REPO (a document naming any other repository is
   * rejected before any verification), the bundle must be signed by that
   * repository's platform-release workflow at a platform tag, and the
   * predicate type and artifact format must both equal `format`. The
   * artifact is parsed from the signed payload bytes.
   */
  async authenticatePlatformEndorsements(bundle: JsonValue, repo: string, tag: string, hexDigest: string, format: string): Promise<PlatformEndorsements> {
    if (format !== ARTIFACT_FORMAT && format !== ARTIFACT_FORMAT_V2) {
      throw new Error(`unsupported platform artifact format ${JSON.stringify(format)}`);
    }
    if (repo !== PLATFORM_ENDORSEMENTS_REPO) {
      throw new Error(`platform endorsements repo ${JSON.stringify(repo)} does not equal ${JSON.stringify(PLATFORM_ENDORSEMENTS_REPO)}`);
    }
    let verified: VerifiedRelease;
    try {
      verified = await this.verifyBundle(bundle, PLATFORM_ENDORSEMENTS_IDENTITY, hexDigest);
    } catch (err) {
      throw new Error(`verifying platform endorsements bundle: ${message(err)}`);
    }
    let predicateType: string;
    let predicate: Uint8Array;
    try {
      ({ predicateType, predicate } = signedPredicate(verified.payload));
    } catch (err) {
      throw new Error(`platform endorsements statement: ${message(err)}`);
    }
    const artifact = parseArtifact(predicate);
    if (predicateType !== format || artifact.format !== format) {
      throw new Error(`platform predicate and artifact must use ${JSON.stringify(format)}`);
    }
    const authenticated = authenticatedArtifact(verified, repo, tag, hexDigest, "platform endorsements");
    return { ...authenticated, artifact };
  }
}

const STATEMENT_MEMBERS = ["_type", "subject", "predicateType", "predicate"];

/**
 * The predicate member of a verified in-toto payload, serialized exactly as
 * it was signed (member order and number literals preserved), so a strict
 * decoder sees the signed bytes. Statement-level strictness was enforced when
 * the bundle was verified; this only extracts the member.
 */
export function signedPredicate(payload: Uint8Array): { predicateType: string; predicate: Uint8Array } {
  const statement = object(strictParse(payload), "statement", STATEMENT_MEMBERS);
  const predicate = statement.get("predicate");
  if (!(predicate instanceof Map)) throw new Error("predicate is not an object");
  return { predicateType: str(statement, "predicateType"), predicate: serialize(predicate) };
}

/** The multi-platform code predicate: the SNP launch measurement, TDX RTMR1 and RTMR2, and the VM shape. */
function codePredicate(payload: Uint8Array): { sevSnp: ExpectedSevSnp; tdx: ExpectedTdx; shape: Shape } {
  const statement = object(strictParse(payload), "statement", STATEMENT_MEMBERS);
  const predicateType = str(statement, "predicateType");
  if (predicateType !== MULTI_PLATFORM_PREDICATE_TYPE) throw new Error(`unsupported predicate type: ${predicateType}`);
  const predicate = statement.get("predicate");
  const fields = predicate instanceof Map ? predicate : new Map<string, JsonValue>();

  const tdxField = fields.get("tdx_measurement");
  if (tdxField === undefined) throw new Error("invalid multiplatform measurement: no tdx measurement");
  if (tdxField === null) throw new Error("invalid multiplatform measurement: tdx measurement is nil");
  if (!(tdxField instanceof Map)) throw new Error("invalid multiplatform measurement: tdx measurement is not a struct");
  const snpField = fields.get("snp_measurement");
  if (snpField === undefined) throw new Error("invalid multiplatform measurement: no snp measurement");
  if (snpField === null) throw new Error("invalid multiplatform measurement: snp measurement is nil");
  for (const rtmr of ["rtmr1", "rtmr2"]) {
    const v = tdxField.get(rtmr);
    if (v === undefined) throw new Error(`invalid multiplatform measurement: no ${rtmr}`);
    if (v === null) throw new Error(`invalid multiplatform measurement: ${rtmr} is nil`);
  }
  const register = (name: string, value: JsonValue | undefined): Uint8Array => {
    // A value that is not a string reads as "" and so fails the length check.
    try {
      return parseRegister(typeof value === "string" ? value : "");
    } catch (err) {
      throw new Error(`invalid multiplatform measurement: ${name}: ${message(err)}`);
    }
  };
  const launch = register("snp measurement", snpField);
  const rtmr1 = register("rtmr1", tdxField.get("rtmr1"));
  const rtmr2 = register("rtmr2", tdxField.get("rtmr2"));
  return { sevSnp: { platform: "sev-snp", launch }, tdx: { platform: "tdx", rtmr1, rtmr2 }, shape: shapeFromPredicate(fields) };
}

const SHAPE_MEMBERS = ["cpus", "memory_mb", "gpus", "disks"] as const;
const TWO_POW_63 = 2 ** 63;

/**
 * The `vm_shape` member: an object whose cpus, memory_mb, gpus and disks are
 * all present and are JSON numbers whose value is a non-negative integer
 * below 2^63. Numbers are read as float64, so a fractional literal with an
 * integral value ("4.0") reads as that integer.
 */
function shapeFromPredicate(fields: JsonObject): Shape {
  const v = fields.get("vm_shape");
  if (v === undefined) throw new Error("code predicate declares no vm_shape");
  if (!(v instanceof Map)) throw new Error("vm_shape is not an object");
  const values: Partial<Record<(typeof SHAPE_MEMBERS)[number], bigint>> = {};
  for (const name of SHAPE_MEMBERS) {
    if (!v.has(name)) throw new Error(`vm_shape is missing ${JSON.stringify(name)}`);
    let f: number;
    try {
      const n = num(v, name);
      f = n === undefined ? NaN : n.toFloat64();
    } catch {
      f = NaN;
    }
    if (!Number.isFinite(f) || f < 0 || f !== Math.trunc(f) || f >= TWO_POW_63) {
      throw new Error(`vm_shape member ${JSON.stringify(name)} is not a non-negative integer`);
    }
    values[name] = BigInt(f);
  }
  return { cpus: values.cpus!, memoryMb: values.memory_mb!, gpus: values.gpus!, disks: values.disks! };
}

/**
 * The release identity a verified bundle proves. A runtime-repository bundle
 * must come from the pinned repository and organization ids; the source ref
 * must be a tag (equal to `tag` when one is given); the commit must be a
 * lowercase Git commit; the statement must name its first subject.
 */
export function authenticatedArtifact(verified: VerifiedRelease, repo: string, tag: string, hexDigest: string, label: string): AuthenticatedArtifact {
  const certificate = verified.identity;
  if (repo === RUNTIME_REPO) {
    if (certificate.sourceRepositoryIdentifier !== RUNTIME_REPO_ID) {
      throw new Error(`${label} source repository ID does not match the pinned repository`);
    }
    if (certificate.sourceRepositoryOwnerIdentifier !== TINFOIL_ORGANIZATION_ID) {
      throw new Error(`${label} source repository owner ID does not match the pinned organization`);
    }
  }
  const ref = certificate.sourceRepositoryRef;
  if (!ref.startsWith(TAG_REF_PREFIX)) throw new Error(`${label} source ref ${JSON.stringify(ref)} is not a tag`);
  const authenticatedTag = ref.slice(TAG_REF_PREFIX.length);
  if (tag !== "" && authenticatedTag !== tag) {
    throw new Error(`${label} source ref ${JSON.stringify(ref)} does not match tag ${JSON.stringify(tag)}`);
  }
  const commit = certificate.sourceRepositoryDigest;
  if (!GIT_COMMIT_RE.test(commit)) throw new Error(`${label} source digest is not a lowercase Git commit`);
  const first = verified.subjects[0];
  if (first === undefined || first.name === "") throw new Error(`${label} statement has no named subject`);
  return { repo, tag: authenticatedTag, commit, subjectName: first.name, digest: hexDigest.toLowerCase() };
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
