import { PredicateType } from './types.js';
import type { AttestationMeasurement } from './types.js';
import type { X509Certificate, VerificationPolicy } from '@freedomofpress/sigstore-browser';
import sigstoreTrustedRoot from './sigstore-trusted-root.json' with { type: 'json' };
import { VerificationError, wrapOrThrow } from './errors.js';

class GitHubWorkflowRefPattern implements VerificationPolicy {
  private pattern: RegExp;

  constructor(pattern: string | RegExp) {
    this.pattern = typeof pattern === 'string' ? new RegExp(pattern) : pattern;
  }

  verify(cert: X509Certificate): void {
    const ext = cert.extGitHubWorkflowRef;
    if (!ext) {
      throw new VerificationError('Certificate does not contain GitHubWorkflowRef extension');
    }
    if (!this.pattern.test(ext.workflowRef)) {
      throw new VerificationError(
        `Certificate's GitHubWorkflowRef "${ext.workflowRef}" does not match pattern "${this.pattern}"`
      );
    }
  }
}

/**
 * Verifies the attested measurements of an enclave image against a trusted root (Sigstore)
 * and returns the measurement payload contained in the DSSE.
 *
 * @param bundleJson - The bundle JSON data
 * @param digest - The expected hex-encoded SHA256 digest of the DSSE payload
 * @param repo - The repository name
 * @returns The verified measurement data
 * @throws Error if verification fails or digests don't match
 */
export async function verifySigstoreAttestation(
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
      throw new VerificationError(`Unsupported payload type: ${payloadType}. Only supports In-toto.`);
    }

    const predicateType = payload.predicateType as PredicateType;
    const predicateFields = payload.predicate;

    // Manual Payload Digest Verification
    // Now, verify that the provided external digest matches the
    // actual digest in the payload returned from the verified envelope
    if (digest !== payload.subject[0].digest.sha256) {
      throw new VerificationError(
        `Provided digest does not match verified DSSE payload digest. Expected: ${digest}, Got: ${payload.subject[0].digest.sha256}`
      );
    }

    // Convert predicate type to measurement type
    let registers: string[];

    if (!predicateFields) {
      throw new VerificationError('Payload does not contain predicate');
    }

    if (predicateType === PredicateType.SnpTdxMultiplatformV1) {
      if (!predicateFields.snp_measurement) {
        throw new VerificationError('SNP TDX Multiplatform V1 predicate does not contain snp_measurement');
      }
      registers = [predicateFields.snp_measurement];
    } else {
      throw new VerificationError(`Unsupported predicate type: ${predicateType}`);
    }

    return {
      type: predicateType,
      registers,
    };

  } catch (e) {
    wrapOrThrow(e, VerificationError, 'Reference data verification failed');
  }
}
