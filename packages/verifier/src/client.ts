import { verifyAttestation as verifyAmdAttestation } from './attestation.js';
import { verifySigstoreBundle } from './sigstore.js';
import { assembleAttestationBundle } from './bundle.js';
import { verifyCertificate } from './cert-verify.js';
import { compareMeasurements, measurementFingerprint } from './types.js';
import type { AttestationResponse, VerificationDocument, AttestationBundle } from './types.js';
import { ConfigurationError } from './errors.js';

export interface VerifierOptions {
  /** Server URL for fetching attestation. Required when using verify(), optional when using verifyBundle(). */
  serverURL?: string;
  configRepo: string;
}

export class Verifier {
  private serverURL?: string;
  private configRepo: string;
  private verificationDocument?: VerificationDocument;

  constructor(options: VerifierOptions) {
    if (!options.configRepo) {
      throw new ConfigurationError("configRepo is required for Verifier");
    }
    this.serverURL = options.serverURL;
    this.configRepo = options.configRepo;
  }

  async verify(): Promise<AttestationResponse> {
    if (!this.serverURL) {
      throw new ConfigurationError("serverURL is required for verify(). Use verifyBundle() with an attestation bundle instead.");
    }
    const domain = new URL(this.serverURL).hostname;
    const bundle = await assembleAttestationBundle(domain, this.configRepo);
    return this.verifyBundle(bundle);
  }

  async verifyBundle(bundle: AttestationBundle): Promise<AttestationResponse> {
    const { enclaveAttestationReport: attestationDoc, vcek, digest, sigstoreBundle, domain, enclaveCert } = bundle;

    const steps: VerificationDocument['steps'] = {
      fetchDigest: { status: 'success' }, // Already fetched by caller
      verifyCode: { status: 'pending' },
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

      // Step 2: Verify code provenance (Sigstore bundle)
      let codeMeasurements;
      try {
        codeMeasurements = await verifySigstoreBundle(sigstoreBundle, digest, this.configRepo);
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
