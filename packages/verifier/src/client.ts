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
   * provenance must be established out of band. It must carry the register
   * layout of its type (1 for SEV-SNP, 3 for multi-platform) as 48-byte hex,
   * and is validated and copied at construction.
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
    if (!this.serverURL) {
      throw new ConfigurationError("serverURL is required for verify(). Use verifyBundle() with an attestation bundle instead.");
    }
    // The certificate is checked against the hostname; the fetch keeps any
    // explicit port so attestation comes from the same origin as requests.
    const serverURL = new URL(this.serverURL);
    const domain = serverURL.hostname;
    if (this.pinnedMeasurement) {
      const material = await fetchEnclaveAttestationMaterial(serverURL.host);
      return this.verifyBundle({ domain, ...material });
    }
    const bundle = await assembleAttestationBundle(serverURL.host, this.configRepo);
    return this.verifyBundle({ ...bundle, domain });
  }

  async verifyBundle(bundle: VerifiableAttestationBundle): Promise<AttestationResponse> {
    const { enclaveAttestationReport: attestationDoc, vcek, releaseTag: selectedReleaseTag, sigstoreBundle, domain, enclaveCert } = bundle;
    const pinned = this.pinnedMeasurement;

    const steps: VerificationDocument['steps'] = {
      fetchDigest: { status: pinned ? 'skipped' : 'success' }, // Already fetched by caller
      verifyCode: { status: pinned ? 'skipped' : 'pending' },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
      verifyCertificate: { status: 'pending' },
    };

    try {
      // Step 1: Verify enclave attestation
      let amdVerification: AttestationResponse;
      try {
        amdVerification = await verifyAmdAttestation(attestationDoc, vcek);
        steps.verifyEnclave = { status: 'success' };
      } catch (error) {
        steps.verifyEnclave = { status: 'failed', error: (error as Error).message };
        this.saveFailedVerificationDocument(steps, domain);
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
          this.saveFailedVerificationDocument(steps, domain);
          throw error;
        }
      }

      // Step 3: Compare measurements
      try {
        compareMeasurements(codeMeasurements, amdVerification.measurement);
        steps.compareMeasurements = { status: 'success' };
      } catch (error) {
        steps.compareMeasurements = { status: 'failed', error: (error as Error).message };
        this.saveFailedVerificationDocument(steps, domain);
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
        this.saveFailedVerificationDocument(steps, domain);
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

      return amdVerification;
    } catch (error) {
      if (!this.verificationDocument) {
        this.saveFailedVerificationDocument(steps, domain);
      }
      throw error;
    }
  }

  private saveFailedVerificationDocument(steps: VerificationDocument['steps'], domain: string): void {
    this.verificationDocument = {
      schemaVersion: VERIFICATION_DOCUMENT_SCHEMA_VERSION,
      configRepo: this.configRepo,
      enclaveHost: domain,
      releaseDigest: '',
      codeMeasurement: { type: '', registers: [] },
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
