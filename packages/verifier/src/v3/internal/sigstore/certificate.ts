/**
 * Certificate-signed bundle verification: the Sigstore library proves the
 * chain, certificate-transparency, log inclusion, timestamps and the DSSE
 * signature; this module adds the signing-identity policy and reads the
 * source-repository claims the verifier binds artifacts to.
 */
import { notImplemented } from "../../errors.js";
import type { Bundle } from "./bundle.js";
import type { TrustedRoot } from "./trusted-root.js";

export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
export const RUNNER_ENVIRONMENT_GITHUB_HOSTED = "github-hosted";

/** The claims a GitHub Actions signing certificate carries. */
export interface SigningIdentity {
  /** The SAN URI: https://github.com/<repo>/.github/workflows/<file>@<ref>. */
  readonly subjectAlternativeName: string;
  readonly issuer: string;
  readonly runnerEnvironment: string;
  readonly sourceRepositoryIdentifier: string;
  readonly sourceRepositoryOwnerIdentifier: string;
  readonly sourceRepositoryRef: string;
  readonly sourceRepositoryDigest: string;
}

/** What verification proved about a certificate-signed bundle. */
export interface VerifiedBundle {
  readonly identity: SigningIdentity;
  readonly payload: Uint8Array;
  /** The earliest transparency-log integration time, when an entry carries one. */
  readonly earliestLogTime?: Date;
}

/**
 * Verifies a certificate-signed DSSE bundle against `root`: the certificate
 * chain, at least one SCT, at least one log entry with inclusion proven, at
 * least one observer timestamp, the DSSE signature, that no two SCTs come from
 * the same log, that the SAN matches `sanPattern`, the issuer is GitHub and
 * the runner is GitHub-hosted, and that the statement's subject carries
 * `digestHex` (as subject 0, or as the subject named `subjectName`).
 */
export async function verifyCertificateBundle(
  root: TrustedRoot,
  bundle: Bundle,
  sanPattern: RegExp,
  digestHex: string,
  subjectName?: string,
): Promise<VerifiedBundle> {
  return notImplemented("sigstore.verifyCertificateBundle");
}

/** Builds the anchored SAN pattern for a workflow file and ref pattern in `repo`. */
export function workflowIdentityPattern(repo: string, workflowPattern: string, refPattern: string): RegExp {
  return notImplemented("sigstore.workflowIdentityPattern");
}
