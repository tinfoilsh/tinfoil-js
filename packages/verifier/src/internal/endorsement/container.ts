/** Provenance of a container image whose build its config requires. */
import { object, str } from "../json/decode.js";
import { strictParse, type JsonValue } from "../json/index.js";
import type { ContainerProvenance } from "../runtime/provenance.js";
import type { IdentityPattern } from "../sigstore/certificate.js";
import { IN_TOTO_STATEMENT_V1 } from "./approval.js";
import type { ProvenanceClient, VerifiedRelease } from "./provenance.js";
import { GIT_COMMIT_RE } from "./reference.js";
import { SLSA_PROVENANCE_V1 } from "./runtime.js";

const GITHUB_REPOSITORY_URL_PREFIX = "https://github.com/";
const WORKFLOWS_PATH = "/.github/workflows/";
const IDENTITY_REF_SEPARATOR = "@";
/** The pattern character a container requirement uses for any run of characters within one ref segment. */
const REF_WILDCARD = "*";
/** The characters a wildcard never matches: the ref segment separator and the identity's ref separator. */
const REF_WILDCARD_EXCLUDED = "/" + IDENTITY_REF_SEPARATOR;
const STATEMENT_MEMBERS = ["_type", "subject", "predicateType", "predicate"];

/** A container image whose build was authenticated against the requirement its config declares. */
export interface Container {
  readonly digest: string;
  readonly repository: string;
  readonly workflow: string;
  /** The ref the workflow ran from, as the signing certificate states it. */
  readonly ref: string;
  /** Lowercase 40-hex Git commit. */
  readonly commit: string;
}

/**
 * Verifies that `bundle` is a SLSA build attestation for the required image
 * digest, signed by the required workflow of the required repository on a
 * GitHub-hosted runner.
 */
export async function authenticateContainer(client: ProvenanceClient, bundle: JsonValue, required: ContainerProvenance): Promise<Container> {
  let verified: VerifiedRelease;
  try {
    verified = await client.verifyBundle(bundle, containerIdentity(required), required.digest);
  } catch (err) {
    throw new Error(`verifying container provenance: ${err instanceof Error ? err.message : String(err)}`);
  }
  return authenticatedContainer(verified, required);
}

/**
 * The signing identities a requirement accepts: the required workflow file
 * of the required repository, run from a ref its pattern matches. The
 * repository and workflow compare as literals, and the whole identity must
 * match.
 */
export function containerIdentity(required: ContainerProvenance): IdentityPattern {
  const prefix = GITHUB_REPOSITORY_URL_PREFIX + required.repository + WORKFLOWS_PATH + required.workflow + IDENTITY_REF_SEPARATOR;
  return { test: (san) => san.startsWith(prefix) && refMatches(required.ref, san.slice(prefix.length)) };
}

/** The container a verified bundle proves, once its statement and source claims meet the requirement. */
export function authenticatedContainer(verified: Pick<VerifiedRelease, "identity" | "payload">, required: ContainerProvenance): Container {
  const statement = object(strictParse(verified.payload), "statement", STATEMENT_MEMBERS);
  if (str(statement, "_type") !== IN_TOTO_STATEMENT_V1 || str(statement, "predicateType") !== SLSA_PROVENANCE_V1) {
    throw new Error("container provenance must use SLSA v1");
  }
  if (!(statement.get("predicate") instanceof Map)) throw new Error("container provenance predicate is not an object");
  // The signing identity names the workflow file that ran, which a workflow
  // in another repository can call. The source claims name the repository
  // and ref that triggered the run.
  const certificate = verified.identity;
  if (certificate.sourceRepositoryURI !== GITHUB_REPOSITORY_URL_PREFIX + required.repository) {
    throw new Error(`container provenance source repository ${JSON.stringify(certificate.sourceRepositoryURI)} does not match ${JSON.stringify(required.repository)}`);
  }
  if (certificate.sourceRepositoryIdentifier !== required.repositoryID) {
    throw new Error("container provenance source repository ID does not match the required repository");
  }
  if (!refMatches(required.ref, certificate.sourceRepositoryRef)) {
    throw new Error(`container provenance source ref ${JSON.stringify(certificate.sourceRepositoryRef)} does not match ${JSON.stringify(required.ref)}`);
  }
  if (!GIT_COMMIT_RE.test(certificate.sourceRepositoryDigest)) throw new Error("container provenance source digest is not a lowercase Git commit");
  return {
    digest: required.digest,
    repository: required.repository,
    workflow: required.workflow,
    ref: certificate.sourceRepositoryRef,
    commit: certificate.sourceRepositoryDigest,
  };
}

/**
 * Reports whether the whole of `ref` matches a requirement's ref pattern:
 * each "*" matches any run of characters other than "/" and "@", and every
 * other character matches itself. It is the anchored regular expression
 * that replaces each "*" with `[^/@]*`, matched without backtracking over
 * more than one wildcard, so that a certificate cannot make it slow.
 */
export function refMatches(pattern: string, ref: string): boolean {
  let p = 0;
  let r = 0;
  // The last wildcard passed and the end of the run it has matched so far.
  let wildcard = -1;
  let run = 0;
  while (r < ref.length) {
    if (pattern[p] === REF_WILDCARD) {
      wildcard = p++;
      run = r;
    } else if (pattern[p] === ref[r]) {
      p++;
      r++;
    } else if (wildcard >= 0 && !REF_WILDCARD_EXCLUDED.includes(ref[run]!)) {
      // Only the last wildcard's run grows: the literals before it stay at
      // their first match, which leaves the most of the ref for the rest of
      // the pattern.
      p = wildcard + 1;
      r = ++run;
    } else {
      return false;
    }
  }
  while (pattern[p] === REF_WILDCARD) p++;
  return p === pattern.length;
}
