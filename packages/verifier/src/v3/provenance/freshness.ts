// Freshness witness verification (Go: verifier/provenance/freshness.go): a
// freshness proof is a Sigstore bundle signed under the pinned
// freshness-witness identity whose in-toto statement endorses exactly the
// authenticated artifact, anchored in time by its transparency-log entry.

import { decodeBase64 } from "../bytes.js";
import { VerificationError } from "../errors.js";
import { arrayOf, field, mapOf, str, structOf, unmarshal, type Schema } from "../strictjson.js";
import { parseBundle } from "./bundle-format.js";
import {
  freshnessWitnessIdentity,
  repoNameRE,
  verifyBundleWithIdentity,
  type AuthenticatedArtifact,
  type ProvenanceOpts,
} from "./provenance.js";

export const FreshnessPredicateFormat = "https://tinfoil.sh/predicate/freshness-witness/v1";
const inTotoStatementV1 = "https://in-toto.io/Statement/v1";
export const MaxFreshnessAge = 7 * 24 * 60 * 60 * 1000; // ms
export const MaxFreshnessFutureSkew = 5 * 60 * 1000; // ms

const sha256DigestRE = /^sha256:[0-9a-f]{64}$/;
const commitRE = /^[0-9a-f]{40}$/;
const artifactDigestRE = /^[0-9a-f]{64}$/;

interface FreshnessSubject {
  name: string;
  digest: Map<string, string>;
}

export interface WitnessSubject {
  name: string;
  digest: string;
}

export interface WitnessEndorsement {
  repo: string;
  tag: string;
  commit: string;
  subject: WitnessSubject;
}

export interface FreshnessWitness {
  format: string;
  endorses: WitnessEndorsement;
}

interface FreshnessStatement {
  type: string;
  subject?: FreshnessSubject[];
  predicateType: string;
  predicate: FreshnessWitness;
}

const freshnessStatementSchema: Schema = structOf({
  _type: field("type", str),
  subject: field(
    "subject",
    arrayOf(
      structOf({
        name: field("name", str),
        digest: field("digest", mapOf(str)),
      }),
    ),
  ),
  predicateType: field("predicateType", str),
  predicate: field(
    "predicate",
    structOf({
      format: field("format", str),
      endorses: field(
        "endorses",
        structOf({
          repo: field("repo", str),
          tag: field("tag", str),
          commit: field("commit", str),
          subject: field(
            "subject",
            structOf({
              name: field("name", str),
              digest: field("digest", str),
            }),
          ),
        }),
      ),
    }),
  ),
});

function provErr(message: string): VerificationError {
  return new VerificationError("PROVENANCE_REJECTED", message);
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// authenticateFreshness verifies a freshness witness bundle for the given
// authenticated artifact and returns the verified transparency-log time
// (Go: Client.AuthenticateFreshness).
export async function authenticateFreshness(
  bundleJSON: Uint8Array,
  expected: AuthenticatedArtifact,
  now: Date,
  opts?: ProvenanceOpts,
): Promise<Date> {
  validateAuthenticatedArtifact(expected);
  let result;
  try {
    result = await verifyBundleWithIdentity(bundleJSON, freshnessWitnessIdentity, expected.digest, opts);
  } catch (err) {
    throw provErr(`verifying freshness witness bundle: ${errMsg(err)}`);
  }
  const statement = parseFreshnessStatement(bundleJSON);
  if (statement.type !== inTotoStatementV1) {
    throw provErr(`unexpected freshness statement type ${JSON.stringify(statement.type)}`);
  }
  if (statement.predicateType !== FreshnessPredicateFormat || statement.predicate.format !== FreshnessPredicateFormat) {
    throw provErr("unexpected freshness predicate format");
  }
  const subjects = statement.subject ?? [];
  if (
    subjects.length !== 1 ||
    subjects[0].name !== expected.subjectName ||
    subjects[0].digest.get("sha256") !== expected.digest
  ) {
    throw provErr("freshness statement subject does not match authenticated artifact");
  }
  validateWitness(statement.predicate, expected);
  return validateFreshnessTime(result.tlogTimestamps, now);
}

function validateAuthenticatedArtifact(expected: AuthenticatedArtifact | null | undefined): void {
  if (expected == null) {
    throw provErr("authenticated artifact is nil");
  }
  if (!repoNameRE.test(expected.repo)) {
    throw provErr("authenticated artifact repository is invalid");
  }
  if (expected.tag === "") {
    throw provErr("authenticated artifact tag is empty");
  }
  if (!commitRE.test(expected.commit)) {
    throw provErr("authenticated artifact commit is malformed");
  }
  if (expected.subjectName === "") {
    throw provErr("authenticated artifact subject name is empty");
  }
  if (!artifactDigestRE.test(expected.digest)) {
    throw provErr("authenticated artifact digest is malformed");
  }
}

// validateFreshnessTime appraises the earliest verified transparency-log
// timestamp against the pinned appraisal time.
function validateFreshnessTime(timestamps: Date[], now: Date): Date {
  let loggedAt: Date | undefined;
  for (const timestamp of timestamps) {
    if (loggedAt === undefined || timestamp.getTime() < loggedAt.getTime()) {
      loggedAt = timestamp;
    }
  }
  if (loggedAt === undefined) {
    throw provErr("freshness witness has no verified transparency-log timestamp");
  }
  if (loggedAt.getTime() > now.getTime() + MaxFreshnessFutureSkew) {
    throw provErr("freshness witness timestamp is in the future");
  }
  if (now.getTime() - loggedAt.getTime() > MaxFreshnessAge) {
    throw provErr("freshness witness is stale");
  }
  return loggedAt;
}

function parseFreshnessStatement(bundleJSON: Uint8Array): FreshnessStatement {
  const parsed = parseBundle(bundleJSON);
  const envelope = parsed.dsseEnvelope;
  if (envelope == null) {
    throw provErr("freshness bundle has no DSSE envelope");
  }
  let payload: Uint8Array;
  try {
    payload = decodeBase64(envelope.payload ?? "");
  } catch (err) {
    throw provErr(`parsing freshness bundle: ${errMsg(err)}`);
  }
  try {
    return unmarshal(payload, freshnessStatementSchema) as FreshnessStatement;
  } catch (err) {
    throw provErr(`parsing freshness statement: ${errMsg(err)}`);
  }
}

function validateWitness(witness: FreshnessWitness, expected: AuthenticatedArtifact): void {
  if (
    witness.endorses.repo !== expected.repo ||
    witness.endorses.tag !== expected.tag ||
    witness.endorses.commit !== expected.commit ||
    witness.endorses.subject.name !== expected.subjectName ||
    witness.endorses.subject.digest !== "sha256:" + expected.digest
  ) {
    throw provErr("freshness witness does not match authenticated artifact");
  }
  if (!sha256DigestRE.test(witness.endorses.subject.digest)) {
    throw provErr("freshness witness subject digest is malformed");
  }
}
