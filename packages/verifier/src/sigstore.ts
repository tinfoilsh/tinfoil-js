import { PredicateType } from './types.js';
import type { AttestationMeasurement } from './types.js';
import type { X509Certificate, VerificationPolicy } from '@freedomofpress/sigstore-browser';
import sigstoreTrustedRoot from './sigstore-trusted-root.json' with { type: 'json' };
import { AttestationError, wrapOrThrow } from './errors.js';

class GitHubWorkflowRefPattern implements VerificationPolicy {
  private pattern: RegExp;

  constructor(pattern: string | RegExp) {
    this.pattern = typeof pattern === 'string' ? new RegExp(pattern) : pattern;
  }

  verify(cert: X509Certificate): void {
    const ext = cert.extGitHubWorkflowRef;
    if (!ext) {
      throw new AttestationError('Sigstore certificate verification failed: Missing GitHub workflow reference extension');
    }
    if (!this.pattern.test(ext.workflowRef)) {
      throw new AttestationError(
        `Sigstore certificate verification failed: Workflow reference "${ext.workflowRef}" does not match expected pattern (must be a tagged release)`
      );
    }
  }
}

/**
 * Verifies a Sigstore bundle.
 * Validates the DSSE envelope signature, certificate identity policy,
 * Rekor log consistency, and extracts the measurement payload.
 *
 * @param bundleJson - The Sigstore bundle JSON data
 * @param digest - The expected hex-encoded SHA256 digest of the DSSE payload
 * @param repo - The repository name
 * @returns The verified measurement data
 * @throws Error if verification fails or digests don't match
 */
export async function verifySigstoreBundle(
  bundleJson: unknown,
  digest: string,
  repo: string
): Promise<AttestationMeasurement> {

  try {
    const {
      SigstoreVerifier,
      GITHUB_OIDC_ISSUER,
      AllOf,
      OIDCIssuer,
      GitHubWorkflowRepository,
    } = await import('@freedomofpress/sigstore-browser');

    const verifier = new SigstoreVerifier();
    // Use bundled Sigstore trusted root instead of fetching via TUF
    // This avoids CORS issues in browsers since tuf-repo-cdn.sigstore.dev doesn't support CORS
    await verifier.loadSigstoreRoot(sigstoreTrustedRoot);

    const bundle = bundleJson as any;

    // Create policy for GitHub Actions certificate identity
    const policy = new AllOf([
      new OIDCIssuer(GITHUB_OIDC_ISSUER),
      new GitHubWorkflowRepository(repo),
      new GitHubWorkflowRefPattern(/^refs\/tags\//),
    ]);

    // Verify the DSSE envelope and get the payload
    // This verifies the signature on the DSSE envelope, applies the
    // certificate identity policy, and checks Rekor log consistency.
    // It returns the verified payload from within the envelope.
    const { payloadType, payload: payloadBytes } = await verifier.verifyDsse(bundle, policy);

    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

    if (payloadType !== 'application/vnd.in-toto+json') {
      throw new AttestationError(`Unsupported Sigstore payload type: "${payloadType}". Only in-toto attestation format is supported`);
    }

    const predicateType = payload.predicateType as PredicateType;
    const predicateFields = payload.predicate;

    // Manual Payload Digest Verification
    // Now, verify that the provided external digest matches the
    // actual digest in the payload returned from the verified envelope
    if (digest !== payload.subject[0].digest.sha256) {
      throw new AttestationError(
        `Release digest mismatch: The release digest from GitHub (${digest}) does not match the digest in the sigstore bundle (${payload.subject[0].digest.sha256})`
      );
    }

    // Convert predicate type to measurement type
    let registers: string[];

    if (!predicateFields) {
      throw new AttestationError('Invalid Sigstore bundle: Payload is missing the predicate field containing measurements');
    }

    if (predicateType === PredicateType.SnpTdxMultiplatformV1) {
      if (!predicateFields.snp_measurement) {
        throw new AttestationError('Invalid Sigstore bundle: SNP/TDX multiplatform predicate is missing the snp_measurement field');
      }
      registers = [predicateFields.snp_measurement];
    } else {
      throw new AttestationError(`Unsupported attestation predicate type: "${predicateType}". Only SNP/TDX multiplatform V1 is supported`);
    }

    return {
      type: predicateType,
      registers,
    };

  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Sigstore code bundle verification failed');
  }
}
