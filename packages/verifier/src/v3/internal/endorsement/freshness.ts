/**
 * The freshness witness for a code or platform release: an independently
 * signed statement that the artifact was recently published. The witness is
 * a certificate-signed bundle from the freshness-witness workflow; its time
 * is the transparency log's integration time of the bundle's first log
 * entry, which the log vouched for with an inclusion promise.
 */
import { map, object, str, struct } from "../json/decode.js";
import { strictParse, type JsonValue } from "../json/index.js";
import { FRESHNESS_WITNESS_IDENTITY, type ProvenanceClient } from "./provenance.js";
import { validateAuthenticatedArtifact, type AuthenticatedArtifact } from "./reference.js";

export const FRESHNESS_PREDICATE_FORMAT = "https://tinfoil.sh/predicate/freshness-witness/v1";
export const MAX_FRESHNESS_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_FRESHNESS_FUTURE_SKEW_MS = 5 * 60 * 1000;

const IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1";
const SHA256_DIGEST_PREFIX = "sha256:";

const STATEMENT_MEMBERS = ["_type", "subject", "predicateType", "predicate"];
const SUBJECT_MEMBERS = ["name", "digest"];
const PREDICATE_MEMBERS = ["format", "endorses"];
const ENDORSES_MEMBERS = ["repo", "tag", "commit", "subject"];
const WITNESS_SUBJECT_MEMBERS = ["name", "digest"];

/** The release a witness statement endorses. */
export interface WitnessEndorsement {
  readonly repo: string;
  readonly tag: string;
  readonly commit: string;
  readonly subject: { readonly name: string; readonly digest: string };
}

interface FreshnessStatement {
  readonly type: string;
  readonly subjects: readonly { readonly name: string; readonly sha256: string }[];
  readonly predicateType: string;
  readonly format: string;
  readonly endorses: WitnessEndorsement;
}

/**
 * Verifies a witness bundle signed by the freshness-witness workflow, whose
 * statement endorses exactly `expected` (repo, tag, commit, subject name and
 * digest), and whose log time is no more than `maxAgeMs` before `now` and no
 * more than five minutes after it. Returns that log time.
 */
export async function authenticateFreshness(
  client: ProvenanceClient,
  bundle: JsonValue,
  expected: AuthenticatedArtifact,
  now: Date,
  maxAgeMs: number,
): Promise<Date> {
  if (!(maxAgeMs >= 0)) throw new Error("freshness maximum age must not be negative");
  validateAuthenticatedArtifact(expected);
  let verified;
  try {
    verified = await client.verifyBundle(bundle, FRESHNESS_WITNESS_IDENTITY, expected.digest);
  } catch (err) {
    throw new Error(`verifying freshness witness bundle: ${err instanceof Error ? err.message : String(err)}`);
  }
  const statement = parseFreshnessStatement(verified.payload);
  if (statement.type !== IN_TOTO_STATEMENT_V1) {
    throw new Error(`unexpected freshness statement type ${JSON.stringify(statement.type)}`);
  }
  if (statement.predicateType !== FRESHNESS_PREDICATE_FORMAT || statement.format !== FRESHNESS_PREDICATE_FORMAT) {
    throw new Error("unexpected freshness predicate format");
  }
  const subject = statement.subjects[0];
  if (statement.subjects.length !== 1 || subject === undefined || subject.name !== expected.subjectName || subject.sha256 !== expected.digest) {
    throw new Error("freshness statement subject does not match authenticated artifact");
  }
  validateWitness(statement.endorses, expected);
  return validateFreshnessTime(loggedAt(verified.bundle.tlogEntries), now, maxAgeMs || MAX_FRESHNESS_AGE_MS);
}

/**
 * The integration time of the first log entry, when the log vouched for it
 * with an inclusion promise (the promise that bundle verification checked);
 * undefined otherwise.
 */
function loggedAt(entries: readonly { readonly integratedTime?: bigint; readonly inclusionPromise?: Uint8Array }[]): Date | undefined {
  const first = entries[0];
  if (first === undefined || first.integratedTime === undefined || first.inclusionPromise === undefined) return undefined;
  return new Date(Number(first.integratedTime) * 1000);
}

/** `loggedAt` must exist, lie no more than five minutes after `now`, and no more than `maxAgeMs` before it. */
export function validateFreshnessTime(loggedAt: Date | undefined, now: Date, maxAgeMs: number): Date {
  if (loggedAt === undefined || !Number.isFinite(loggedAt.getTime())) {
    throw new Error("freshness witness has no verified transparency-log timestamp");
  }
  if (loggedAt.getTime() > now.getTime() + MAX_FRESHNESS_FUTURE_SKEW_MS) throw new Error("freshness witness timestamp is in the future");
  if (now.getTime() - loggedAt.getTime() > maxAgeMs) throw new Error("freshness witness is stale");
  return loggedAt;
}

/** Strict decode of the witness statement; a member outside the profile rejects. */
export function parseFreshnessStatement(payload: Uint8Array): FreshnessStatement {
  try {
    const s = object(strictParse(payload), "freshness statement", STATEMENT_MEMBERS);
    const subjects = subjectsOf(s.get("subject"));
    const predicate = struct(s, "predicate", PREDICATE_MEMBERS);
    const endorses = struct(predicate, "endorses", ENDORSES_MEMBERS);
    const witnessSubject = struct(endorses, "subject", WITNESS_SUBJECT_MEMBERS);
    return {
      type: str(s, "_type"),
      subjects,
      predicateType: str(s, "predicateType"),
      format: str(predicate, "format"),
      endorses: {
        repo: str(endorses, "repo"),
        tag: str(endorses, "tag"),
        commit: str(endorses, "commit"),
        subject: { name: str(witnessSubject, "name"), digest: str(witnessSubject, "digest") },
      },
    };
  } catch (err) {
    throw new Error(`parsing freshness statement: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function subjectsOf(list: JsonValue | undefined): { name: string; sha256: string }[] {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new Error("subject is not an array");
  return list.map((item, i) => {
    const subject = object(item, `subject[${i}]`, SUBJECT_MEMBERS);
    const digests = map(subject, "digest", (v) => {
      if (v === null) return "";
      if (typeof v !== "string") throw new Error(`subject[${i}] digest is not a string`);
      return v;
    });
    return { name: str(subject, "name"), sha256: digests.get("sha256") ?? "" };
  });
}

/** The witness must endorse exactly the authenticated artifact, with its digest in "sha256:" form. */
export function validateWitness(witness: WitnessEndorsement, expected: AuthenticatedArtifact): void {
  if (
    witness.repo !== expected.repo ||
    witness.tag !== expected.tag ||
    witness.commit !== expected.commit ||
    witness.subject.name !== expected.subjectName ||
    witness.subject.digest !== SHA256_DIGEST_PREFIX + expected.digest
  ) {
    throw new Error("freshness witness does not match authenticated artifact");
  }
}
