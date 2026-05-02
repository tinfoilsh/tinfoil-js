import { PredicateType } from './types.js';
import type { AttestationMeasurement, HardwareMeasurement } from './types.js';
import type { X509Certificate, VerificationPolicy } from '@freedomofpress/sigstore-browser';
import sigstoreTrustedRoot from './sigstore-trusted-root.js';
import { AttestationError, FetchError, wrapOrThrow } from './errors.js';

const GITHUB_PROXY = 'https://github-proxy.tinfoil.sh';
const HARDWARE_MEASUREMENTS_REPO = 'tinfoilsh/hardware-measurements';

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

async function verifyAndExtractPayload(
  bundleJson: unknown,
  digest: string,
  repo: string,
): Promise<{ predicateType: PredicateType; predicateFields: any }> {
  const {
    SigstoreVerifier,
    GITHUB_OIDC_ISSUER,
    AllOf,
    OIDCIssuer,
    GitHubWorkflowRepository,
  } = await import('@freedomofpress/sigstore-browser');

  const verifier = new SigstoreVerifier({
    ctlogThreshold: 1,
    tlogThreshold: 1,
  });
  await verifier.loadSigstoreRoot(sigstoreTrustedRoot);

  const bundle = bundleJson as any;

  const policy = new AllOf([
    new OIDCIssuer(GITHUB_OIDC_ISSUER),
    new GitHubWorkflowRepository(repo),
    new GitHubWorkflowRefPattern(/^refs\/tags\//),
  ]);

  const { payloadType, payload: payloadBytes } = await verifier.verifyDsse(bundle, policy);
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

  if (payloadType !== 'application/vnd.in-toto+json') {
    throw new AttestationError(`Unsupported Sigstore payload type: "${payloadType}". Only in-toto statements (application/vnd.in-toto+json) are supported`);
  }

  const bundleDigest = payload.subject?.[0]?.digest?.sha256;
  if (!bundleDigest) {
    throw new AttestationError('Invalid Sigstore bundle: Payload is missing subject digest');
  }
  if (digest !== bundleDigest) {
    throw new AttestationError(
      `Release digest mismatch: The release digest from GitHub (${digest}) does not match the digest in the sigstore bundle (${bundleDigest})`
    );
  }

  const predicateType = payload.predicateType as PredicateType;
  const predicateFields = payload.predicate;

  if (!predicateFields) {
    throw new AttestationError('Invalid Sigstore bundle: Payload is missing the predicate field containing measurements');
  }

  return { predicateType, predicateFields };
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
    const { predicateType, predicateFields } = await verifyAndExtractPayload(bundleJson, digest, repo);

    let registers: string[];

    if (predicateType === PredicateType.SnpTdxMultiplatformV1) {
      if (!predicateFields.snp_measurement) {
        throw new AttestationError('Invalid Sigstore bundle: SNP/TDX multiplatform predicate is missing the snp_measurement field');
      }

      const tdxMeasurement = predicateFields.tdx_measurement;
      if (!tdxMeasurement || !tdxMeasurement.rtmr1 || !tdxMeasurement.rtmr2) {
        throw new AttestationError('Invalid Sigstore bundle: SNP/TDX multiplatform predicate is missing tdx_measurement rtmr1/rtmr2 fields');
      }

      registers = [
        predicateFields.snp_measurement,
        tdxMeasurement.rtmr1,
        tdxMeasurement.rtmr2,
      ];
    } else {
      throw new AttestationError(`Unsupported in-toto predicate type: "${predicateType}". Only SNP/TDX multiplatform V1 is supported`);
    }

    return {
      type: predicateType,
      registers,
    };

  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Sigstore code bundle verification failed');
  }
}

/**
 * Fetches and verifies hardware measurements from the tinfoilsh/hardware-measurements repo.
 * Validates the Sigstore bundle and extracts MRTD/RTMR0 for each platform.
 */
export async function fetchHardwareMeasurements(): Promise<HardwareMeasurement[]> {
  try {
    const latestResp = await fetch(`${GITHUB_PROXY}/repos/${HARDWARE_MEASUREMENTS_REPO}/releases/latest`);
    if (!latestResp.ok) throw new FetchError(`HTTP ${latestResp.status}: failed to fetch latest hardware measurements release`);
    const { tag_name } = await latestResp.json();

    const hashResp = await fetch(`${GITHUB_PROXY}/${HARDWARE_MEASUREMENTS_REPO}/releases/download/${tag_name}/tinfoil.hash`);
    if (!hashResp.ok) throw new FetchError(`HTTP ${hashResp.status}: failed to fetch hardware measurements digest`);
    const digest = (await hashResp.text()).trim();

    const bundleResp = await fetch(`${GITHUB_PROXY}/repos/${HARDWARE_MEASUREMENTS_REPO}/attestations/sha256:${digest}`);
    if (!bundleResp.ok) throw new FetchError(`HTTP ${bundleResp.status}: failed to fetch hardware measurements attestation bundle`);
    const data = await bundleResp.json();
    if (!data.attestations?.[0]?.bundle) {
      throw new FetchError(`No Sigstore bundle for hardware measurements at digest ${digest}`);
    }

    const { predicateType, predicateFields } = await verifyAndExtractPayload(
      data.attestations[0].bundle, digest, HARDWARE_MEASUREMENTS_REPO
    );

    if (predicateType !== PredicateType.HardwareMeasurementsV1) {
      throw new AttestationError(`Unexpected predicate type for hardware measurements: ${predicateType}`);
    }

    const measurements: HardwareMeasurement[] = [];
    for (const [key, value] of Object.entries(predicateFields)) {
      const fields = value as any;
      if (!fields.mrtd || !fields.rtmr0) {
        throw new AttestationError('Invalid hardware measurement: missing mrtd or rtmr0');
      }
      measurements.push({
        ID: `${key}@${digest}`,
        MRTD: fields.mrtd,
        RTMR0: fields.rtmr0,
      });
    }

    return measurements;
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Hardware measurements verification failed');
  }
}
