import { verifyAttestation as verifyEnclaveAttestation } from './attestation.js';
import { verifySigstoreBundle, fetchHardwareMeasurements } from './sigstore.js';
import { assembleAttestationBundle } from './bundle.js';
import { verifyCertificate } from './cert-verify.js';
import { compareMeasurements, measurementFingerprint, PredicateType } from './types.js';
import { verifyHardware } from './hardware.js';
import type { AttestationResponse, VerificationDocument, AttestationBundle, AttestationMeasurement, HardwareMeasurement } from './types.js';
import { AttestationError, ConfigurationError } from './errors.js';

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
    const { enclaveVerification, codeMeasurements, steps, digest } = await this.coreVerify(bundle);

    let matchedHw: HardwareMeasurement | null = null;

    if (enclaveVerification.measurement.type === PredicateType.TdxGuestV2) {
      const hwMeasurements = await fetchHardwareMeasurements();
      matchedHw = verifyHardware(hwMeasurements, enclaveVerification.measurement);
    }

    const enclaveType = enclaveVerification.measurement.type;
    const codeFingerprint = await measurementFingerprint(codeMeasurements, matchedHw, enclaveType);
    const enclaveFingerprint = await measurementFingerprint(enclaveVerification.measurement, matchedHw, enclaveType);

    this.verificationDocument = {
      configRepo: this.configRepo,
      enclaveHost: domain,
      releaseDigest: digest,
      codeMeasurement: codeMeasurements,
      enclaveMeasurement: enclaveVerification,
      tlsPublicKey: enclaveVerification.tlsPublicKeyFingerprint || '',
      hpkePublicKey: enclaveVerification.hpkePublicKey || '',
      hardwareMeasurement: matchedHw ?? undefined,
      codeFingerprint,
      enclaveFingerprint,
      selectedRouterEndpoint: domain,
      securityVerified: true,
      steps
    };

    return enclaveVerification;
  }

  async verifyBundle(bundle: AttestationBundle): Promise<AttestationResponse> {
    const { enclaveVerification, codeMeasurements, steps, domain, digest } = await this.coreVerify(bundle);

    const enclaveType = enclaveVerification.measurement.type;
    const codeFingerprint = await measurementFingerprint(codeMeasurements, null, enclaveType);
    const enclaveFingerprint = await measurementFingerprint(enclaveVerification.measurement, null, enclaveType);

    this.verificationDocument = {
      configRepo: this.configRepo,
      enclaveHost: domain,
      releaseDigest: digest,
      codeMeasurement: codeMeasurements,
      enclaveMeasurement: enclaveVerification,
      tlsPublicKey: enclaveVerification.tlsPublicKeyFingerprint || '',
      hpkePublicKey: enclaveVerification.hpkePublicKey || '',
      codeFingerprint,
      enclaveFingerprint,
      selectedRouterEndpoint: domain,
      securityVerified: true,
      steps
    };

    return enclaveVerification;
  }

  private async coreVerify(bundle: AttestationBundle): Promise<{
    enclaveVerification: AttestationResponse;
    codeMeasurements: AttestationMeasurement;
    steps: VerificationDocument['steps'];
    domain: string;
    digest: string;
  }> {
    const { enclaveAttestationReport: attestationDoc, vcek, digest, sigstoreBundle, domain, enclaveCert } = bundle;

    const steps: VerificationDocument['steps'] = {
      fetchDigest: { status: 'success' },
      verifyCode: { status: 'pending' },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
      verifyCertificate: { status: 'pending' },
    };

    try {
      // Step 1: Verify enclave attestation (SEV-SNP or TDX)
      let enclaveVerification: AttestationResponse;
      try {
        enclaveVerification = await verifyEnclaveAttestation(attestationDoc, vcek);
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
        compareMeasurements(codeMeasurements, enclaveVerification.measurement);
        steps.compareMeasurements = { status: 'success' };
      } catch (error) {
        steps.compareMeasurements = { status: 'failed', error: (error as Error).message };
        this.saveFailedVerificationDocument(steps, domain);
        throw error;
      }

      // Step 4: Verify certificate
      try {
        if (!enclaveCert) {
          throw new AttestationError('Enclave certificate is required');
        }
        await verifyCertificate(
          enclaveCert,
          domain,
          attestationDoc,
          enclaveVerification.hpkePublicKey || ''
        );
        steps.verifyCertificate = { status: 'success' };
      } catch (error) {
        steps.verifyCertificate = { status: 'failed', error: (error as Error).message };
        this.saveFailedVerificationDocument(steps, domain);
        throw error;
      }

      return { enclaveVerification, codeMeasurements, steps, domain, digest };
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
