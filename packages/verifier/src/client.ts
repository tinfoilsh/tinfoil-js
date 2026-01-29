import { verifyAttestation as verifyAmdAttestation, fetchAttestation } from './attestation.js';
import { fetchLatestDigest, fetchGithubAttestationBundle } from './github.js';
import { verifySigstoreAttestation } from './sigstore.js';
import { verifyCertificate, CertificateVerificationError } from './cert-verify.js';
import { compareMeasurements, FormatMismatchError, MeasurementMismatchError, measurementFingerprint } from './types.js';
import type { AttestationDocument, AttestationMeasurement, AttestationResponse, VerificationDocument, AttestationBundle } from './types.js';

export interface VerifierOptions {
  /** Server URL for fetching attestation. Required when using verify(), optional when using verifyBundle(). */
  serverURL?: string;
  configRepo: string;
}

export class Verifier {
  private enclave: string;
  private configRepo: string;
  private verificationDocument?: VerificationDocument;

  constructor(options: VerifierOptions) {
    if (!options.configRepo) {
      throw new Error("configRepo is required for Verifier");
    }
    this.enclave = options.serverURL ? new URL(options.serverURL).hostname : '';
    this.configRepo = options.configRepo;
  }

  async verify(): Promise<AttestationResponse> {
    if (!this.enclave) {
      throw new Error("serverURL is required for verify(). Use verifyBundle() with an attestation bundle instead.");
    }
    const attestationDoc = await fetchAttestation(this.enclave);
    const digest = await fetchLatestDigest(this.configRepo);
    const sigstoreBundle = await fetchGithubAttestationBundle(this.configRepo, digest);

    return this.performVerification(attestationDoc, undefined, digest, sigstoreBundle, this.enclave);
  }

  async verifyBundle(bundle: AttestationBundle): Promise<AttestationResponse> {
    return this.performVerification(
      bundle.enclaveAttestationReport,
      bundle.vcek,
      bundle.digest,
      bundle.sigstoreBundle,
      bundle.domain,
      bundle.enclaveCert
    );
  }

  private async performVerification(
    attestationDoc: AttestationDocument,
    vcek: string | undefined,
    digest: string,
    sigstoreBundle: unknown,
    domain: string,
    enclaveCert?: string
  ): Promise<AttestationResponse> {
    const steps: VerificationDocument['steps'] = {
      fetchDigest: { status: 'success' }, // Already fetched by caller
      verifyCode: { status: 'pending' },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
      verifyCertificate: enclaveCert ? { status: 'pending' } : undefined,
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

      // Step 2: Verify code attestation (Sigstore)
      let codeMeasurements: AttestationMeasurement;
      try {
        codeMeasurements = await verifySigstoreAttestation(sigstoreBundle, digest, this.configRepo);
        steps.verifyCode = { status: 'success' };
      } catch (error) {
        steps.verifyCode = { status: 'failed', error: (error as Error).message };
        this.saveFailedVerificationDocument(steps, domain);
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
        this.saveFailedVerificationDocument(steps, domain);
        throw error;
      }

      // Step 4: Verify certificate (if provided)
      if (enclaveCert) {
        try {
          await verifyCertificate(
            enclaveCert,
            domain,
            attestationDoc,
            amdVerification.hpkePublicKey || ''
          );
          steps.verifyCertificate = { status: 'success' };
        } catch (error) {
          if (error instanceof CertificateVerificationError) {
            steps.verifyCertificate = { status: 'failed', error: error.message };
          } else {
            steps.verifyCertificate = { status: 'failed', error: (error as Error).message };
          }
          this.saveFailedVerificationDocument(steps, domain);
          throw error;
        }
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
        this.saveFailedVerificationDocument(steps, domain);
      }
      throw error;
    }
  }

  private saveFailedVerificationDocument(steps: VerificationDocument['steps'], domain: string): void {
    this.verificationDocument = {
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
      steps
    };
  }

  getVerificationDocument(): VerificationDocument | undefined {
    return this.verificationDocument;
  }
}
