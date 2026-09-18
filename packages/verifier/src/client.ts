import { verifyAttestation as verifyAmdAttestation } from './attestation.js';
import { verifySigstoreBundle } from './sigstore.js';
import { assembleAttestationBundle, fetchEnclaveAttestationMaterial } from './bundle.js';
import { verifyCertificate } from './cert-verify.js';
import { compareMeasurements, measurementFingerprint } from './types.js';
import type { AttestationResponse, AttestationMeasurement, VerificationDocument, AttestationBundle, SoftwareIdentity } from './types.js';
import { ConfigurationError } from './errors.js';
import { cloneVerificationDocument } from './json.js';
import { validatePinnedMeasurement } from './pin.js';
import { VERIFICATION_DOCUMENT_SCHEMA_VERSION, VERIFIER_NAME, VERIFIER_VERSION } from './version.js';

/**
 * Sentinel values recorded in the verification document when the expected
 * measurement was pinned by the caller rather than derived from a release.
 */
export const PINNED_NO_REPO = 'pinned_no_repo';
export const PINNED_NO_DIGEST = 'pinned_no_digest';

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
    let domain = '';
    let bundle: VerifiableAttestationBundle;
    try {
      if (!this.serverURL) {
        throw new ConfigurationError("serverURL is required for verify(). Use verifyBundle() with an attestation bundle instead.");
      }
      // The certificate is checked against the hostname; the fetch keeps any
      // explicit port so attestation comes from the same origin as requests.
      const serverURL = new URL(this.serverURL);
      domain = serverURL.hostname;
      this.saveUnverifiedDocument(steps, domain);
      if (this.pinnedMeasurement) {
        const material = await fetchEnclaveAttestationMaterial(serverURL.host);
        bundle = { domain, ...material };
      } else {
        const material = await assembleAttestationBundle(serverURL.host, this.configRepo);
        bundle = { ...material, domain };
      }
    } catch (error) {
      steps.otherError = { status: 'failed', error: error instanceof Error ? error.message : String(error) };
      this.saveUnverifiedDocument(steps, domain);
      throw error;
    }
    return this.verifyBundle(bundle);
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
            throw new ConfigurationError("Attestation bundle is missing release provenance (digest, sigstoreBundle)");
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
        steps.otherError = { status: 'failed', error: error instanceof Error ? error.message : String(error) };
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
