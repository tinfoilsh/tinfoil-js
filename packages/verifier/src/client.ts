import { verifyAttestation as verifyAmdAttestation, fetchAttestation } from './attestation.js';
import { fetchLatestDigest, fetchAttestationBundle } from './github.js';
import { verifyAttestation as verifySigstoreAttestation } from './sigstore.js';
import { compareMeasurements, FormatMismatchError, MeasurementMismatchError, measurementFingerprint } from './types.js';
import type { AttestationDocument, AttestationMeasurement, AttestationResponse, VerificationDocument, AttestationBundle } from './types.js';

export interface VerifierOptions {
  serverURL: string;
  configRepo: string;
}

export class Verifier {
  private enclave: string;
  private configRepo: string;
  private verificationDocument?: VerificationDocument;

  constructor(options: VerifierOptions) {
    if (!options.serverURL) {
      throw new Error("serverURL is required for Verifier");
    }
    if (!options.configRepo) {
      throw new Error("configRepo is required for Verifier");
    }
    this.enclave = new URL(options.serverURL).hostname;
    this.configRepo = options.configRepo;
  }

  async verify(): Promise<AttestationResponse> {
    const attestationDoc = await fetchAttestation(this.enclave);
    const digest = await fetchLatestDigest(this.configRepo);
    const sigstoreBundle = await fetchAttestationBundle(this.configRepo, digest);

    return this.performVerification(attestationDoc, undefined, digest, sigstoreBundle, this.enclave);
  }

  async verifyBundle(bundle: AttestationBundle): Promise<AttestationResponse> {
    return this.performVerification(
      bundle.enclaveAttestationReport,
      bundle.vcek,
      bundle.digest,
      bundle.sigstoreBundle,
      bundle.domain
    );
  }

  private async performVerification(
    attestationDoc: AttestationDocument,
    vcek: string | undefined,
    digest: string,
    sigstoreBundle: unknown,
    domain: string
  ): Promise<AttestationResponse> {
    const steps: VerificationDocument['steps'] = {
      fetchDigest: { status: 'success' }, // Already fetched by caller
      verifyCode: { status: 'pending' },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
    };

    this.enclave = domain;

    try {
      // Step 1: Verify enclave attestation
      let amdVerification: AttestationResponse;
      try {
        amdVerification = await verifyAmdAttestation(attestationDoc, vcek);
        steps.verifyEnclave = { status: 'success' };
      } catch (error) {
        steps.verifyEnclave = { status: 'failed', error: (error as Error).message };
        this.saveFailedVerificationDocument(steps);
        throw error;
      }

      // Step 2: Verify code attestation (Sigstore)
      let codeMeasurements: AttestationMeasurement;
      try {
        codeMeasurements = await verifySigstoreAttestation(sigstoreBundle, digest, this.configRepo);
        steps.verifyCode = { status: 'success' };
      } catch (error) {
        steps.verifyCode = { status: 'failed', error: (error as Error).message };
        this.saveFailedVerificationDocument(steps);
        throw error;
      }

      // Step 3: Compare measurements
      try {
        compareMeasurements(codeMeasurements, amdVerification.measurement);
        steps.compareMeasurements = { status: 'success' };
      } catch (error) {
        if (error instanceof FormatMismatchError) {
          steps.compareMeasurements = { status: 'failed', error: error.message };
        } else if (error instanceof MeasurementMismatchError) {
          steps.compareMeasurements = { status: 'failed', error: error.message };
        } else {
          steps.compareMeasurements = { status: 'failed', error: (error as Error).message };
        }
        this.saveFailedVerificationDocument(steps);
        throw error;
      }

      // Build successful verification document
      this.verificationDocument = {
        configRepo: this.configRepo,
        enclaveHost: domain,
        releaseDigest: digest,
        codeMeasurement: codeMeasurements,
        enclaveMeasurement: amdVerification,
        tlsPublicKey: amdVerification.tlsPublicKeyFingerprint || '',
        hpkePublicKey: amdVerification.hpkePublicKey || '',
        codeFingerprint: await measurementFingerprint(codeMeasurements),
        enclaveFingerprint: await measurementFingerprint(amdVerification.measurement),
        selectedRouterEndpoint: domain,
        securityVerified: true,
        steps
      };

      return amdVerification;
    } catch (error) {
      if (!this.verificationDocument) {
        this.saveFailedVerificationDocument(steps);
      }
      throw error;
    }
  }

  private saveFailedVerificationDocument(steps: VerificationDocument['steps']): void {
    this.verificationDocument = {
      configRepo: this.configRepo,
      enclaveHost: this.enclave || '',
      releaseDigest: '',
      codeMeasurement: { type: '', registers: [] },
      enclaveMeasurement: { measurement: { type: '', registers: [] } },
      tlsPublicKey: '',
      hpkePublicKey: '',
      codeFingerprint: '',
      enclaveFingerprint: '',
      selectedRouterEndpoint: this.enclave || '',
      securityVerified: false,
      steps
    };
  }

  getVerificationDocument(): VerificationDocument | undefined {
    return this.verificationDocument;
  }
}
