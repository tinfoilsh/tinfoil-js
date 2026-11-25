/** Provenance of the container images whose build a config requires. */
import { object, str } from "../json/decode.js";
import { strictParse, type JsonValue } from "../json/index.js";
import { configContainerProvenance, type ContainerProvenance } from "../runtime/provenance.js";
import { IN_TOTO_STATEMENT_V1 } from "./approval.js";
import type { ProvenanceClient, VerifiedRelease } from "./provenance.js";
import { SLSA_PROVENANCE_V1 } from "./runtime.js";

/**
 * Accepts every GitHub signing identity. The identity of a container build
 * is compared as text once its bundle verifies.
 */
const GITHUB_IDENTITY = /^https:\/\/github\.com\//;
const GITHUB_URL_PREFIX = "https://github.com/";
const GITHUB_WORKFLOWS_PATH = "/.github/workflows/";
const WORKFLOW_REF_SEPARATOR = "@";

/**
 * Verifies the build of every container image for which `config` requires
 * one. `attestation` returns the Sigstore bundle that a document carries for
 * the image with a lowercase hex SHA-256 digest.
 */
export async function authenticateContainers(client: ProvenanceClient, config: Uint8Array, attestation: (digest: string) => JsonValue): Promise<void> {
  for (const required of configContainerProvenance(config)) {
    const bundle = attestation(required.digest);
    try {
      await authenticateContainer(client, bundle, required);
    } catch (err) {
      throw new Error(`container image sha256:${required.digest}: ${message(err)}`);
    }
  }
}

/**
 * Verifies that `bundle` is a SLSA build attestation of the image with
 * `required.digest`, signed on a GitHub-hosted runner by the required
 * workflow of the required repository, at the required ref and source commit.
 */
export async function authenticateContainer(client: ProvenanceClient, bundle: JsonValue, required: ContainerProvenance): Promise<void> {
  let verified: VerifiedRelease;
  try {
    verified = await client.verifyBundle(bundle, GITHUB_IDENTITY, required.digest);
  } catch (err) {
    throw new Error(`verifying container provenance: ${message(err)}`);
  }
  const statement = object(strictParse(verified.payload), "statement");
  if (str(statement, "_type") !== IN_TOTO_STATEMENT_V1 || str(statement, "predicateType") !== SLSA_PROVENANCE_V1) {
    throw new Error("container provenance must use SLSA v1");
  }
  // The source fields name the repository and ref that the run built. The
  // identity names the workflow file that signed, which must be that
  // repository's own file at that ref and not one called from elsewhere.
  const certificate = verified.identity;
  const repository = GITHUB_URL_PREFIX + required.repository;
  const identity = repository + GITHUB_WORKFLOWS_PATH + required.workflow + WORKFLOW_REF_SEPARATOR + required.ref;
  if (certificate.sourceRepositoryURI !== repository) {
    throw new Error(`container provenance source repository ${JSON.stringify(certificate.sourceRepositoryURI)} is not ${JSON.stringify(repository)}`);
  }
  if (certificate.sourceRepositoryIdentifier !== required.repositoryID) {
    throw new Error(`container provenance source repository ID ${JSON.stringify(certificate.sourceRepositoryIdentifier)} is not ${JSON.stringify(required.repositoryID)}`);
  }
  if (certificate.subjectAlternativeName !== identity) {
    throw new Error(`container provenance workflow identity ${JSON.stringify(certificate.subjectAlternativeName)} is not ${JSON.stringify(identity)}`);
  }
  if (certificate.sourceRepositoryRef !== required.ref) {
    throw new Error(`container provenance source ref ${JSON.stringify(certificate.sourceRepositoryRef)} is not ${JSON.stringify(required.ref)}`);
  }
  if (certificate.sourceRepositoryDigest !== required.commit) {
    throw new Error(`container provenance source commit ${JSON.stringify(certificate.sourceRepositoryDigest)} is not ${JSON.stringify(required.commit)}`);
  }
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
