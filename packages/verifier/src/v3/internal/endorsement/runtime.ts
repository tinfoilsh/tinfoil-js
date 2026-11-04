/** Provenance of the IGVM runtime release pinned by a config. */
import { runtimeReferenceEqual, RUNTIME_REPO, type RuntimeCollateral, type RuntimeReference } from "../../document/collateral/runtime.js";
import { object, str } from "../json/decode.js";
import { strictParse } from "../json/index.js";
import { parseManifest, type Manifest } from "../runtime/manifest.js";
import * as semver from "../semver.js";
import { workflowIdentityPattern } from "../sigstore/certificate.js";
import { authenticatedArtifact, type ProvenanceClient, type VerifiedRelease } from "./provenance.js";
import type { AuthenticatedArtifact } from "./reference.js";

export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
const IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1";
const STATEMENT_MEMBERS = ["_type", "subject", "predicateType", "predicate"];

export interface RuntimeArtifact extends AuthenticatedArtifact {
  readonly manifest: Manifest;
}

/** The manifest subject name of a runtime release at `tag`. */
export function runtimeSubjectName(tag: string): string {
  return `tinfoil-inference-${tag}-manifest.json`;
}

/** The signing identity of a runtime release: the release workflow run from the release tag. */
export function runtimeIdentity(releaseTag: string): RegExp {
  return workflowIdentityPattern(RUNTIME_REPO, "release\\.yml", "refs/tags/" + escapeRegExp(releaseTag));
}

/**
 * Verifies a runtime release: the collateral's reference equals `expected`,
 * the manifest matches the pinned digest and version, and the bundle is
 * signed by the release workflow at the tag, with a SLSA provenance
 * statement naming the manifest as its subject.
 */
export async function authenticateRuntime(client: ProvenanceClient, material: RuntimeCollateral, expected: RuntimeReference): Promise<RuntimeArtifact> {
  if (!runtimeReferenceEqual(material, expected)) throw new Error("runtime collateral does not match the endorsed config's runtime pin");
  const manifest = await parseManifest(material.manifest, expected);
  const subject = runtimeSubjectName(expected.tag);
  const releaseTag = semver.canonical(expected.tag);
  let verified: VerifiedRelease;
  try {
    verified = await client.verifyBundle(material.bundle, runtimeIdentity(releaseTag), expected.digest, subject);
  } catch (err) {
    throw new Error(`verifying runtime provenance: ${err instanceof Error ? err.message : String(err)}`);
  }
  const statement = object(strictParse(verified.payload), "statement", STATEMENT_MEMBERS);
  if (str(statement, "_type") !== IN_TOTO_STATEMENT_V1 || str(statement, "predicateType") !== SLSA_PROVENANCE_V1) {
    throw new Error("runtime provenance must use SLSA v1");
  }
  // A SLSA v1 predicate is an object; a statement that types one but carries none is not provenance.
  if (!(statement.get("predicate") instanceof Map)) throw new Error("runtime provenance predicate is not an object");
  const authenticated = authenticatedArtifact(verified, expected.repo, releaseTag, expected.digest, "runtime");
  return { ...authenticated, subjectName: subject, manifest };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
