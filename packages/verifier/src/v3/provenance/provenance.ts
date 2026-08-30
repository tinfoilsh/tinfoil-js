// Sigstore verification of Tinfoil reference values (Go:
// verifier/provenance/provenance.go): verifies Sigstore-signed bundles
// against the pinned Tinfoil workflow identities, producing verified value
// types — the code measurement (with its declared VM shape) and the
// platform-endorsements artifact.
//
// Core Sigstore verification (cert chain to the Fulcio root of the supplied
// trusted-root JSON, SCT with duplicate-log-id rejection, transparency-log
// entry: inclusion proof + signed checkpoint + SET, observer timestamp within
// certificate validity, DSSE signature under the leaf key) is delegated to
// @freedomofpress/sigstore-browser's SigstoreVerifier.verifyDsse, which
// mirrors sigstore-go's SignedEntityVerifier with
// WithSignedCertificateTimestamps(1) + WithTransparencyLog(1) +
// WithObserverTimestamps(1). Everything sigstore-go does not provide there —
// media-type gate, legacy-layout rejection, signature-count rule, SAN-regex
// certificate identity, artifact-digest policy, statement parsing — is
// implemented here, mirroring the Go code.

import {
  SigstoreVerifier,
  X509Certificate,
  type SigstoreBundle,
  type TrustedRoot,
  type VerificationPolicy,
} from "@freedomofpress/sigstore-browser";

import { decodeBase64, decodeHex, utf8Decode, utf8Encode } from "../bytes.js";
import { VerificationError } from "../errors.js";
import { raw, unmarshal } from "../strictjson.js";
import { SnpTdxMultiPlatformV1, type Measurement } from "../measurement.js";
import { ArtifactFormat, parseArtifact, type Artifact } from "../policy.js";
import { trustedRootJSON } from "../embedded/roots.js";
import {
  parseBundle,
  rejectLegacyBundleFormat,
  requireExactlyOneDSSESignature,
  type WireBundle,
} from "./bundle-format.js";

const oidcIssuer = "https://token.actions.githubusercontent.com";

// platformEndorsementsRepo publishes the platform-endorsements artifact.
const platformEndorsementsRepo = "tinfoilsh/platform-endorsements";
export const freshnessWitnessRepo = "tinfoilsh/freshness-witness";

// platformEndorsementsIdentity is the only signing certificate identity
// accepted for the platform-endorsements artifact: the tag-triggered build
// workflow of the publisher repo. Dots are escaped and the pattern is
// anchored at both ends so no other workflow path, ref type, or trailing SAN
// content can match.
const platformEndorsementsIdentity = githubWorkflowIdentityPattern(
  platformEndorsementsRepo,
  "build\\.yml",
  "refs/tags/v[0-9][^@]*",
);
export const freshnessWitnessIdentity = githubWorkflowIdentityPattern(
  freshnessWitnessRepo,
  "freshness\\.yml",
  "refs/heads/main",
);

// ProvenanceOpts selects the Sigstore trusted-root document; the embedded
// production copy is the default. Verification never fetches trust material
// over the network.
export interface ProvenanceOpts {
  trustRootJSON?: Uint8Array;
}

// AuthenticatedArtifact is release identity recovered from a verified
// Sigstore statement and its signing certificate.
export interface AuthenticatedArtifact {
  repo: string;
  tag: string;
  commit: string;
  subjectName: string;
  digest: string;
}

// Shape is the VM shape a code artifact declares (Go: *policy.Shape with
// GPUs always set by shapeFromPredicate).
export interface Shape {
  cpus: number;
  memoryMB: number;
  gpus: number;
  disks: number;
}

// Code is the verified content of a code-provenance bundle.
export interface Code extends AuthenticatedArtifact {
  // measurement is the attested launch measurement.
  measurement: Measurement;
  // shape is the VM shape the artifact declares.
  shape: Shape;
}

export interface PlatformEndorsements extends AuthenticatedArtifact {
  artifact: Artifact;
}

function provErr(message: string): VerificationError {
  return new VerificationError("PROVENANCE_REJECTED", message);
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// repoNameRE matches a GitHub "owner/name" repository slug.
export const repoNameRE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

// quoteMeta mirrors Go regexp.QuoteMeta for the characters a repo slug can
// carry (only "." needs escaping, but escape the full metacharacter set).
function quoteMeta(s: string): string {
  return s.replace(/[\\.+*?()|[\]{}^$]/g, "\\$&");
}

// signingIdentity returns the anchored SAN regex accepted for artifacts
// signed from repo: one workflow file directly under the repository's
// .github/workflows directory, run from a tag ref. The repository name is
// validated and escaped so it cannot alter the pattern.
function signingIdentity(repo: string): string {
  if (!repoNameRE.test(repo)) {
    throw provErr(`invalid repository name ${JSON.stringify(repo)}`);
  }
  return githubWorkflowIdentityPattern(repo, "[^/@]+", "refs/tags/[^@]+");
}

function githubWorkflowIdentityPattern(repo: string, workflowPattern: string, refPattern: string): string {
  return (
    "^https://github\\.com/" + quoteMeta(repo) + "/\\.github/workflows/" + workflowPattern + "@" + refPattern + "$"
  );
}

// Statement is the in-toto statement recovered from the DSSE payload,
// mirroring sigstore-go's protojson decode into in_toto.Statement.
export interface Statement {
  type: string;
  subject: StatementSubject[];
  predicateType: string;
  // predicate mirrors structpb.Struct fields; undefined when the statement
  // carries a JSON null (nil Struct in Go).
  predicate: Record<string, unknown> | undefined;
}

export interface StatementSubject {
  name: string;
  digest: Record<string, string>;
}

// VerifiedBundle is the JS analogue of the parts of sigstore-go's
// verify.VerificationResult this package consumes.
export interface VerifiedBundle {
  statement: Statement;
  cert: X509Certificate;
  // tlogTimestamps are the Type=="Tlog" observer timestamps: the integrated
  // time of every transparency-log entry whose inclusion promise (SET) is
  // present, so only cryptographically bound times anchor freshness.
  tlogTimestamps: Date[];
}

const inTotoPayloadType = "application/vnd.in-toto+json";

// parseStatement decodes the DSSE payload as an in-toto statement, mirroring
// sigstore-go's Envelope.Statement(): the payload type is pinned, the JSON
// must be valid UTF-8 with no duplicate members anywhere (protojson), unknown
// statement members reject, and member types are enforced.
function parseStatement(b: WireBundle): Statement {
  const env = b.dsseEnvelope;
  if (env == null) {
    throw provErr("bundle does not carry a DSSE envelope");
  }
  if (env.payloadType !== inTotoPayloadType) {
    throw provErr(`unsupported DSSE payload type ${JSON.stringify(env.payloadType)}`);
  }
  let payload: Uint8Array;
  try {
    payload = decodeBase64(env.payload ?? "");
  } catch (err) {
    throw provErr(`decoding DSSE payload: ${errMsg(err)}`);
  }
  let v: unknown;
  try {
    // The raw-schema walk enforces protojson's structural rules: valid
    // UTF-8, no duplicate object members anywhere, no trailing data.
    unmarshal(payload, raw);
    v = JSON.parse(utf8Decode(payload));
  } catch (err) {
    throw provErr(`parsing in-toto statement: ${errMsg(err)}`);
  }
  if (!isPlainObject(v)) {
    throw provErr("in-toto statement is not a JSON object");
  }

  // protojson accepts both the JSON name and the original proto field name.
  const props: Record<string, "type" | "subject" | "predicateType" | "predicate"> = {
    _type: "type",
    type: "type",
    subject: "subject",
    predicateType: "predicateType",
    predicate_type: "predicateType",
    predicate: "predicate",
  };
  const out: { [k: string]: unknown } = {};
  for (const [key, value] of Object.entries(v)) {
    const prop = Object.prototype.hasOwnProperty.call(props, key) ? props[key] : undefined;
    if (prop === undefined) {
      throw provErr(`in-toto statement has unknown member ${JSON.stringify(key)}`);
    }
    if (prop in out) {
      throw provErr(`in-toto statement has duplicate member ${JSON.stringify(key)}`);
    }
    out[prop] = value;
  }

  const type = out.type ?? "";
  if (typeof type !== "string") {
    throw provErr("in-toto statement _type is not a string");
  }
  const predicateType = out.predicateType ?? "";
  if (typeof predicateType !== "string") {
    throw provErr("in-toto statement predicateType is not a string");
  }
  const rawSubject = out.subject ?? null;
  if (rawSubject !== null && !Array.isArray(rawSubject)) {
    throw provErr("in-toto statement subject is not an array");
  }
  const subject = (rawSubject ?? []).map((s) => parseSubject(s));
  const rawPredicate = out.predicate ?? null;
  if (rawPredicate !== null && !isPlainObject(rawPredicate)) {
    throw provErr("in-toto statement predicate is not an object");
  }
  return { type, subject, predicateType, predicate: rawPredicate ?? undefined };
}

const subjectMembers = new Set([
  "name",
  "uri",
  "digest",
  "content",
  "downloadLocation",
  "download_location",
  "mediaType",
  "media_type",
  "annotations",
]);

function parseSubject(s: unknown): StatementSubject {
  if (!isPlainObject(s)) {
    throw provErr("in-toto statement subject entry is not an object");
  }
  for (const key of Object.keys(s)) {
    if (!subjectMembers.has(key)) {
      throw provErr(`in-toto statement subject has unknown member ${JSON.stringify(key)}`);
    }
  }
  const name = s.name ?? "";
  if (typeof name !== "string") {
    throw provErr("in-toto statement subject name is not a string");
  }
  const rawDigest = s.digest ?? null;
  if (rawDigest !== null && !isPlainObject(rawDigest)) {
    throw provErr("in-toto statement subject digest is not an object");
  }
  const digest: Record<string, string> = {};
  for (const [alg, value] of Object.entries(rawDigest ?? {})) {
    if (typeof value !== "string") {
      throw provErr("in-toto statement subject digest value is not a string");
    }
    digest[alg] = value;
  }
  return { name, digest };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// checkCertificateIdentity applies sigstore-go's certificate identity policy:
// SAN regex, exact OIDC issuer (OID .1.8 DER UTF8String, falling back to the
// deprecated .1.1 raw form), and runner_environment == "github-hosted"
// (OID .1.11). runner_environment comes from the OIDC token, so a workflow
// retargeted to self-hosted (operator-controlled) infrastructure cannot
// claim github-hosted.
function checkCertificateIdentity(cert: X509Certificate, sanRegex: string): void {
  const san = cert.subjectAltName;
  if (san === undefined) {
    throw new Error("no Subject Alternative Name found");
  }
  if (!new RegExp(sanRegex).test(san)) {
    throw new Error(`certificate identity ${JSON.stringify(san)} does not match ${JSON.stringify(sanRegex)}`);
  }
  const issuer = cert.extFulcioIssuerV2?.issuer ?? cert.extFulcioIssuerV1?.issuer ?? "";
  if (issuer !== oidcIssuer) {
    throw new Error(`certificate OIDC issuer ${JSON.stringify(issuer)} is not ${JSON.stringify(oidcIssuer)}`);
  }
  const runnerEnvironment = cert.extRunnerEnvironment?.runnerEnvironment ?? "";
  if (runnerEnvironment !== "github-hosted") {
    throw new Error(`certificate runner_environment ${JSON.stringify(runnerEnvironment)} is not "github-hosted"`);
  }
}

// checkArtifactDigest mirrors sigstore-go's verifyEnvelopeWithArtifactDigests
// (WithArtifactDigest: the digest must match SOME subject; every declared
// subject digest must be decodable hex; DoS limits) — the caller then narrows
// to subject[0] via enforceSubject0Digest.
const maxAllowedSubjects = 1024;
const maxAllowedSubjectDigests = 32;

function checkArtifactDigest(statement: Statement, hexDigest: string): void {
  const want = hexDigest.toLowerCase();
  if (statement.subject.length > maxAllowedSubjects) {
    throw provErr(`too many subjects: ${statement.subject.length} > ${maxAllowedSubjects}`);
  }
  let found = false;
  for (const subject of statement.subject) {
    const entries = Object.entries(subject.digest);
    if (entries.length > maxAllowedSubjectDigests) {
      throw provErr(`too many digests: ${entries.length} > ${maxAllowedSubjectDigests}`);
    }
    for (const [alg, value] of entries) {
      try {
        decodeHex(value);
      } catch (err) {
        throw provErr(`unable to decode subject digest: ${errMsg(err)}`);
      }
      if (alg === "sha256" && value.toLowerCase() === want) {
        found = true;
      }
    }
  }
  if (!found) {
    throw provErr("provided artifact digest does not match any digest in statement");
  }
}

// enforceSubject0Digest applies SPEC §5.4: only the FIRST in-toto subject is
// checked against the expected artifact digest; digests are compared
// case-insensitively (lowercase-normalized per SPEC §7.3).
function enforceSubject0Digest(statement: Statement, expectedDigest: string): void {
  if (statement.subject.length === 0) {
    throw provErr("in-toto statement has no subject");
  }
  const got = statement.subject[0].digest["sha256"] ?? "";
  if (got.toLowerCase() !== expectedDigest.toLowerCase()) {
    throw provErr(
      `subject[0] digest ${JSON.stringify(got)} does not match expected artifact digest ${JSON.stringify(expectedDigest)}`,
    );
  }
}

// checkTrustRoot parse-checks a caller-supplied Sigstore trusted-root document
// (Go: NewClientFromJSON; Python: check_trust_root via TrustedRoot.from_json).
// The conformance adapter runs this before any stage so an unparseable trust
// root is malformed input, not a per-stage rejection. It is deliberately a
// lenient structural parse — NOT the full loadSigstoreRoot the verify path
// performs — so a document that parses but does not verify a bundle still
// surfaces as that stage's rejection, matching Go/Python.
export function checkTrustRoot(trustRootJSON: Uint8Array): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(trustRootJSON));
  } catch (err) {
    throw provErr(`parsing trust root: ${errMsg(err)}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw provErr("parsing trust root: not a JSON object");
  }
}

// verifyBundleWithIdentity verifies a Sigstore bundle against an explicit
// signing certificate SAN regex (Go: Client.verifyBundleWithIdentity).
export async function verifyBundleWithIdentity(
  bundleJSON: Uint8Array,
  sanRegex: string,
  hexDigest: string,
  opts?: ProvenanceOpts,
): Promise<VerifiedBundle> {
  const wire = parseBundle(bundleJSON);
  rejectLegacyBundleFormat(wire);
  requireExactlyOneDSSESignature(wire);

  try {
    decodeHex(hexDigest);
  } catch (err) {
    throw provErr(`decoding hex digest: ${errMsg(err)}`);
  }

  const trustRootBytes = opts?.trustRootJSON ?? utf8Encode(trustedRootJSON);
  let trustRoot: TrustedRoot;
  try {
    trustRoot = JSON.parse(utf8Decode(trustRootBytes)) as TrustedRoot;
  } catch (err) {
    throw provErr(`parsing trust root: ${errMsg(err)}`);
  }

  // Thresholds default to 1 tlog entry + 1 SCT, matching Go's
  // WithSignedCertificateTimestamps(1)/WithTransparencyLog(1); the observer
  // timestamp is the tlog integrated time, which verifyDsse requires to fall
  // inside the certificate validity window.
  const verifier = new SigstoreVerifier();
  const policy: VerificationPolicy = {
    verify(cert: X509Certificate): void {
      checkCertificateIdentity(cert, sanRegex);
    },
  };
  try {
    await verifier.loadSigstoreRoot(trustRoot);
    await verifier.verifyDsse(wire as unknown as SigstoreBundle, policy);
  } catch (err) {
    if (err instanceof VerificationError) throw err;
    throw provErr(`verifying: ${errMsg(err)}`);
  }

  const statement = parseStatement(wire);
  checkArtifactDigest(statement, hexDigest);
  enforceSubject0Digest(statement, hexDigest);

  const certB64 = wire.verificationMaterial?.certificate?.rawBytes;
  if (certB64 === undefined || certB64 === "") {
    throw provErr("bundle has no signing certificate");
  }
  let cert: X509Certificate;
  try {
    cert = X509Certificate.parse(decodeBase64(certB64));
  } catch (err) {
    throw provErr(`parsing signing certificate: ${errMsg(err)}`);
  }

  return { statement, cert, tlogTimestamps: tlogObserverTimestamps(wire) };
}

// tlogObserverTimestamps collects the Type=="Tlog" observer timestamps from a
// bundle's transparency-log entries (Go: result.VerifiedTimestamps filtered to
// Tlog). integratedTime is only cryptographically bound when the entry's
// inclusion promise (SET) is present and verified, so require it before
// trusting the time as a freshness anchor. Absent the SET (e.g. a TSA-only
// entry — and the trusted root does carry a TSA), integratedTime is unverified
// and must not anchor freshness (verifier/provenance/freshness.go keeps only
// VERIFIED Tlog timestamps).
export function tlogObserverTimestamps(wire: WireBundle): Date[] {
  const out: Date[] = [];
  for (const entry of wire.verificationMaterial?.tlogEntries ?? []) {
    const set = entry.inclusionPromise?.signedEntryTimestamp;
    if (set != null && set !== "" && entry.integratedTime != null && entry.integratedTime !== "") {
      out.push(new Date(Number(entry.integratedTime) * 1000));
    }
  }
  return out;
}

async function verifyBundle(
  bundleJSON: Uint8Array,
  repo: string,
  hexDigest: string,
  opts?: ProvenanceOpts,
): Promise<VerifiedBundle> {
  const sanRegex = signingIdentity(repo);
  return verifyBundleWithIdentity(bundleJSON, sanRegex, hexDigest, opts);
}

// shapeFromPredicate parses the required vm_shape predicate member.
function shapeFromPredicate(fields: Record<string, unknown>): Shape {
  const v = fields["vm_shape"];
  if (!("vm_shape" in fields)) {
    throw provErr("code predicate declares no vm_shape");
  }
  if (!isPlainObject(v)) {
    throw provErr("vm_shape is not an object");
  }
  const shape = { cpus: 0, memoryMB: 0, gpus: 0, disks: 0 };
  for (const [name, prop] of [
    ["cpus", "cpus"],
    ["memory_mb", "memoryMB"],
    ["gpus", "gpus"],
    ["disks", "disks"],
  ] as [string, keyof Shape][]) {
    if (!(name in v)) {
      throw provErr(`vm_shape is missing ${JSON.stringify(name)}`);
    }
    const f = v[name];
    // Go accepts only a structpb NumberValue that is a non-negative integer
    // representable in an int (< 2^63).
    if (typeof f !== "number" || !Number.isFinite(f) || f < 0 || f !== Math.trunc(f) || f >= 2 ** 63) {
      throw provErr(`vm_shape member ${JSON.stringify(name)} is not a non-negative integer`);
    }
    shape[prop] = f;
  }
  return shape;
}

// structpb.Value.GetStringValue: "" unless the value is a JSON string.
function stringValue(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function measurementFromStatement(statement: Statement): Measurement {
  const predicateFields = statement.predicate ?? {};

  const measurementType = statement.predicateType;
  switch (measurementType) {
    case SnpTdxMultiPlatformV1: {
      if (!("tdx_measurement" in predicateFields)) {
        throw provErr("invalid multiplatform measurement: no tdx measurement");
      }
      const tdxMeasurement = predicateFields["tdx_measurement"];
      if (!isPlainObject(tdxMeasurement)) {
        throw provErr("invalid multiplatform measurement: tdx measurement is not a struct");
      }
      const rtmrs = tdxMeasurement;

      if (!("snp_measurement" in predicateFields)) {
        throw provErr("invalid multiplatform measurement: no snp measurement");
      }

      for (const rtmr of ["rtmr1", "rtmr2"]) {
        if (!(rtmr in rtmrs)) {
          throw provErr(`invalid multiplatform measurement: no ${rtmr}`);
        }
      }

      return {
        type: measurementType,
        registers: [
          stringValue(predicateFields["snp_measurement"]),
          stringValue(rtmrs["rtmr1"]),
          stringValue(rtmrs["rtmr2"]),
        ],
      };
    }
    default:
      throw provErr(`unsupported predicate type: ${statement.predicateType}`);
  }
}

function authenticatedArtifact(
  result: VerifiedBundle,
  repo: string,
  tag: string,
  hexDigest: string,
  label: string,
): AuthenticatedArtifact {
  if (result.cert == null) {
    throw provErr(`${label} bundle has no signing certificate`);
  }
  const sourceRepositoryRef = result.cert.extSourceRepositoryRef?.sourceRepositoryRef ?? "";
  const tagRefPrefix = "refs/tags/";
  if (!sourceRepositoryRef.startsWith(tagRefPrefix)) {
    throw provErr(`${label} source ref ${JSON.stringify(sourceRepositoryRef)} is not a tag`);
  }
  const authenticatedTag = sourceRepositoryRef.slice(tagRefPrefix.length);
  if (tag !== "" && authenticatedTag !== tag) {
    throw provErr(
      `${label} source ref ${JSON.stringify(sourceRepositoryRef)} does not match tag ${JSON.stringify(tag)}`,
    );
  }
  const commit = result.cert.extSourceRepositoryDigest?.sourceRepositoryDigest ?? "";
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw provErr(`${label} source digest is not a lowercase Git commit`);
  }
  if (result.statement.subject.length === 0 || result.statement.subject[0].name === "") {
    throw provErr(`${label} statement has no named subject`);
  }
  return {
    repo,
    tag: authenticatedTag,
    commit,
    subjectName: result.statement.subject[0].name,
    digest: hexDigest,
  };
}

// authenticateCode authenticates a code-provenance bundle against the repo's
// signing identity and the expected artifact digest, and returns the verified
// code measurement plus the VM shape the artifact declares (required).
export async function authenticateCode(
  bundleJSON: Uint8Array,
  repo: string,
  tag: string,
  hexDigest: string,
  opts?: ProvenanceOpts,
): Promise<Code> {
  let result: VerifiedBundle;
  try {
    result = await verifyBundle(bundleJSON, repo, hexDigest, opts);
  } catch (err) {
    throw provErr(`verifying bundle: ${errMsg(err)}`);
  }
  let measurement: Measurement;
  let shape: Shape;
  try {
    measurement = measurementFromStatement(result.statement);
    shape = shapeFromPredicate(result.statement.predicate ?? {});
  } catch (err) {
    throw provErr(`code predicate: ${errMsg(err)}`);
  }
  const authenticated = authenticatedArtifact(result, repo, tag, hexDigest, "code");
  return { ...authenticated, measurement, shape };
}

// authenticatePlatformEndorsements authenticates a platform-endorsements
// bundle against the publisher's pinned signing identity and returns the
// parsed, validated artifact.
export async function authenticatePlatformEndorsements(
  bundleJSON: Uint8Array,
  repo: string,
  tag: string,
  hexDigest: string,
  opts?: ProvenanceOpts,
): Promise<PlatformEndorsements> {
  let result: VerifiedBundle;
  try {
    result = await verifyBundleWithIdentity(bundleJSON, platformEndorsementsIdentity, hexDigest, opts);
  } catch (err) {
    throw provErr(`verifying platform endorsements bundle: ${errMsg(err)}`);
  }

  if (result.statement.predicateType !== ArtifactFormat) {
    throw provErr(`unexpected predicate type: ${result.statement.predicateType}`);
  }

  // Go re-serializes the verified predicate (protojson.Marshal) and hands it
  // to the fail-closed artifact parser; duplicate members were already
  // rejected during statement parsing.
  const predicateJSON = JSON.stringify(result.statement.predicate ?? null);
  const artifact = parseArtifact(utf8Encode(predicateJSON));
  if (repo !== platformEndorsementsRepo) {
    throw provErr(
      `platform endorsements repo ${JSON.stringify(repo)} does not equal ${JSON.stringify(platformEndorsementsRepo)}`,
    );
  }
  const authenticated = authenticatedArtifact(result, repo, tag, hexDigest, "platform endorsements");
  return { ...authenticated, artifact };
}
