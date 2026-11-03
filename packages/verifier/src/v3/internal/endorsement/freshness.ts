/**
 * The freshness witness for a code or platform release: an independently
 * signed statement that the artifact was recently published.
 */
import { notImplemented } from "../../errors.js";
import type { JsonValue } from "../json/index.js";
import type { ProvenanceClient } from "./provenance.js";
import type { AuthenticatedArtifact } from "./reference.js";

export const FRESHNESS_PREDICATE_FORMAT = "https://tinfoil.sh/predicate/freshness-witness/v1";
export const MAX_FRESHNESS_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_FRESHNESS_FUTURE_SKEW_MS = 5 * 60 * 1000;

/**
 * Verifies a witness bundle signed by the freshness-witness workflow, whose
 * statement endorses exactly `expected` (repo, tag, commit, subject name and
 * digest), and whose earliest log time is no more than `maxAgeMs` before
 * `now` and no more than five minutes after it. Returns that log time.
 */
export async function authenticateFreshness(
  client: ProvenanceClient,
  bundle: JsonValue,
  expected: AuthenticatedArtifact,
  now: Date,
  maxAgeMs: number,
): Promise<Date> {
  return notImplemented("endorsement.authenticateFreshness");
}
