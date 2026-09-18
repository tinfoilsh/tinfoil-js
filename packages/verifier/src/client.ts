import { verifyAttestation as verifyAmdAttestation } from './attestation.js';
import { verifySigstoreBundle } from './sigstore.js';
import { fetchEnclaveAttestationMaterial, fetchReleaseProvenance } from './bundle.js';
import { verifyCertificate } from './cert-verify.js';
import { compareMeasurements, measurementFingerprint } from './types.js';
import type { AttestationResponse, AttestationMeasurement, VerificationDocument, AttestationBundle, SoftwareIdentity } from './types.js';
import { AttestationError, ConfigurationError } from './errors.js';
import { cloneVerificationDocument } from './json.js';
import { validatePinnedMeasurement } from './pin.js';
import { VERIFICATION_DOCUMENT_SCHEMA_VERSION, VERIFIER_NAME, VERIFIER_VERSION } from './version.js';

/**
 * Sentinel values recorded in the verification document when the expected
 * measurement was pinned by the caller rather than derived from a release.
 */
export const PINNED_NO_REPO = 'pinned_no_repo';
export const PINNED_NO_DIGEST = 'pinned_no_digest';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function verifierIdentity(): SoftwareIdentity {
  return { name: VERIFIER_NAME, version: VERIFIER_VERSION };
}

export interface VerifierOptions {
  /** Server URL for fetching attestation. Required when using verify(), optional when using verifyBundle(). */
  serverURL?: string;
  /** GitHub repo whose latest signed release provides the expected measurement. Required unless pinnedMeasurement is set. */
  configRepo?: string;
  /**
   * Expected enclave measurement supplied by the caller. When set, the GitHub
   * release lookup and Sigstore code verification are skipped and the enclave
   * measurement is compared directly against this value. The measurement's
   * provenance must be established out of band. It must be an SEV-SNP guest
   * measurement (`PredicateType.SevGuestV2`, one 48-byte hex register), and
   * is validated and copied at construction.
   */
  pinnedMeasurement?: AttestationMeasurement;
}

/**
 * Attestation material accepted by verifyBundle(). Release provenance
 * (digest, releaseTag, sigstoreBundle) is only required without a pinned
 * measurement.
 */
export type VerifiableAttestationBundle = Omit<AttestationBundle, 'digest' | 'releaseTag' | 'sigstoreBundle'> &
  Partial<Pick<AttestationBundle, 'digest' | 'releaseTag' | 'sigstoreBundle'>>;

export class Verifier {
  private serverURL?: string;
  private configRepo: string;
  private pinnedMeasurement?: AttestationMeasurement;
  private verificationDocument?: VerificationDocument;

  constructor(options: VerifierOptions) {
    // Only omission means "not pinned": a supplied null or malformed pin is a
    // configuration error, not a fallback to release-based verification.
    if (options.pinnedMeasurement !== undefined) {
      if (options.configRepo) {
        throw new ConfigurationError("configRepo and pinnedMeasurement are mutually exclusive");
      }
      this.pinnedMeasurement = validatePinnedMeasurement(options.pinnedMeasurement);
      this.configRepo = PINNED_NO_REPO;
    } else {
      if (!options.configRepo) {
        throw new ConfigurationError("configRepo is required for Verifier");
      }
      this.configRepo = options.configRepo;
    }
    this.serverURL = options.serverURL;
  }

  async verify(): Promise<AttestationResponse> {
    const steps = this.startVerificationAttempt();
    if (!this.serverURL) {
      const error = new ConfigurationError("serverURL is required for verify(). Use verifyBundle() with an attestation bundle instead.");
      steps.otherError = { status: 'failed', error: error.message };
      this.saveUnverifiedDocument(steps, '');
      throw error;
    }
    let serverURL: URL;
    try {
      serverURL = new URL(this.serverURL);
    } catch (cause) {
      const error = new ConfigurationError(`serverURL must be a valid URL. Got: ${this.serverURL}`, { cause: cause as Error });
      steps.otherError = { status: 'failed', error: error.message };
      this.saveUnverifiedDocument(steps, '');
      throw error;
    }
    // The certificate is checked against the hostname; the fetch keeps any
    // explicit port so attestation comes from the same origin as requests.
    const domain = serverURL.hostname;
    this.saveUnverifiedDocument(steps, domain);

    // The two halves are fetched separately so a failure lands on the step it
    // belongs to: enclave material on verifyEnclave (as the Go verifier does),
    // release provenance on fetchDigest.
    const materialPromise = fetchEnclaveAttestationMaterial(serverURL.host);
    const provenancePromise = this.pinnedMeasurement ? undefined : fetchReleaseProvenance(this.configRepo);
    const [materialResult, provenanceResult] = await Promise.allSettled([materialPromise, provenancePromise]);

    if (materialResult.status === 'rejected') {
      steps.verifyEnclave = { status: 'failed', error: errorMessage(materialResult.reason) };
    }
    if (provenanceResult.status === 'rejected') {
      steps.fetchDigest = { status: 'failed', error: errorMessage(provenanceResult.reason) };
    }
    if (materialResult.status === 'rejected' || provenanceResult.status === 'rejected') {
      this.saveUnverifiedDocument(steps, domain);
      throw materialResult.status === 'rejected' ? materialResult.reason : (provenanceResult as PromiseRejectedResult).reason;
    }

    return this.verifyBundle({ domain, ...materialResult.value, ...provenanceResult.value });
  }

  async verifyBundle(bundle: VerifiableAttestationBundle): Promise<AttestationResponse> {
    const steps = this.startVerificationAttempt();
    const pinned = this.pinnedMeasurement;
    let domain = '';

    try {
      const { enclaveAttestationReport: attestationDoc, vcek, releaseTag: selectedReleaseTag, sigstoreBundle, enclaveCert } = bundle;
      domain = bundle.domain;
      this.saveUnverifiedDocument(steps, domain);
      if (!pinned && bundle.digest !== undefined) {
        steps.fetchDigest = { status: 'success' };
      }
      // Step 1: Verify enclave attestation
      let amdVerification: AttestationResponse;
      try {
        amdVerification = await verifyAmdAttestation(attestationDoc, vcek);
        steps.verifyEnclave = { status: 'success' };
      } catch (error) {
        steps.verifyEnclave = { status: 'failed', error: (error as Error).message };
        throw error;
      }

      // Step 2: Establish the expected code measurement, either pinned by the
      // caller or proven by the release's Sigstore bundle
      let codeMeasurements: AttestationMeasurement;
      let releaseTag: string | undefined;
      let digest: string;
      if (pinned) {
        codeMeasurements = pinned;
        digest = PINNED_NO_DIGEST;
      } else {
        try {
          if (bundle.digest === undefined || sigstoreBundle === undefined) {
            // Malformed bundle material is an attestation failure like any other
            // bad input from the bundle service, so it keeps the same retry
            // classification rather than being treated as caller misconfiguration.
            const message = 'Attestation bundle is missing release provenance (digest, sigstoreBundle)';
            steps.fetchDigest = { status: 'failed', error: message };
            throw new AttestationError(message);
          }
          digest = bundle.digest;
          const verifiedCode = await verifySigstoreBundle(
            sigstoreBundle,
            digest,
            this.configRepo,
            selectedReleaseTag
          );
          codeMeasurements = verifiedCode.measurement;
          releaseTag = verifiedCode.releaseTag;
          steps.verifyCode = { status: 'success' };
        } catch (error) {
          steps.verifyCode = { status: 'failed', error: (error as Error).message };
          throw error;
        }
      }

      // Step 3: Compare measurements
      try {
        compareMeasurements(codeMeasurements, amdVerification.measurement);
        steps.compareMeasurements = { status: 'success' };
      } catch (error) {
        steps.compareMeasurements = { status: 'failed', error: (error as Error).message };
        throw error;
      }

      // Step 4: Verify certificate
      try {
        await verifyCertificate(
          enclaveCert,
          domain,
          attestationDoc,
          amdVerification.hpkePublicKey || ''
        );
        steps.verifyCertificate = { status: 'success' };
      } catch (error) {
        steps.verifyCertificate = { status: 'failed', error: (error as Error).message };
        throw error;
      }

      // Build successful verification document
      this.verificationDocument = {
        schemaVersion: VERIFICATION_DOCUMENT_SCHEMA_VERSION,
        configRepo: this.configRepo,
        enclaveHost: domain,
        releaseTag,
        releaseDigest: digest,
        codeMeasurement: codeMeasurements,
        enclaveMeasurement: amdVerification,
        tlsPublicKey: amdVerification.tlsPublicKeyFingerprint || '',
        hpkePublicKey: amdVerification.hpkePublicKey || '',
        codeFingerprint: await measurementFingerprint(codeMeasurements),
        enclaveFingerprint: await measurementFingerprint(amdVerification.measurement),
        selectedRouterEndpoint: domain,
        securityVerified: true,
        verifier: verifierIdentity(),
        verifiedAt: new Date().toISOString(),
        steps
      };

      return structuredClone(amdVerification);
    } catch (error) {
      if (!Object.values(steps).some(step => step?.status === 'failed')) {
        steps.otherError = { status: 'failed', error: errorMessage(error) };
      }
      this.saveUnverifiedDocument(steps, domain);
      throw error;
    }
  }

  private startVerificationAttempt(): VerificationDocument['steps'] {
    const provenanceStatus = this.pinnedMeasurement ? 'skipped' : 'pending';
    const steps: VerificationDocument['steps'] = {
      fetchDigest: { status: provenanceStatus },
      verifyCode: { status: provenanceStatus },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
      verifyCertificate: { status: 'pending' },
    };
    this.saveUnverifiedDocument(steps, '');
    return steps;
  }

  private saveUnverifiedDocument(steps: VerificationDocument['steps'], domain: string): void {
    const pinned = this.pinnedMeasurement;
    this.verificationDocument = {
      schemaVersion: VERIFICATION_DOCUMENT_SCHEMA_VERSION,
      configRepo: this.configRepo,
      enclaveHost: domain,
      releaseDigest: pinned ? PINNED_NO_DIGEST : '',
      codeMeasurement: pinned
        ? { type: pinned.type, registers: [...pinned.registers] }
        : { type: '', registers: [] },
      enclaveMeasurement: { measurement: { type: '', registers: [] } },
      tlsPublicKey: '',
      hpkePublicKey: '',
      codeFingerprint: '',
      enclaveFingerprint: '',
      selectedRouterEndpoint: domain,
      securityVerified: false,
      verifier: verifierIdentity(),
      steps
    };
  }

  getVerificationDocument(): VerificationDocument | undefined {
    return this.verificationDocument
      ? cloneVerificationDocument(this.verificationDocument)
      : undefined;
  }
}
