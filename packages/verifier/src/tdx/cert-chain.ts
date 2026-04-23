import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { uint8ArrayEqual } from '@freedomofpress/crypto-browser';
import { INTEL_SGX_ROOT_CA_PEM } from './constants.js';
import { AttestationError, wrapOrThrow } from '../errors.js';

export class PckCertificateChain {
  constructor(
    public pckLeaf: X509Certificate,
    public intermediate: X509Certificate,
    public root: X509Certificate,
    private trustedRoot: X509Certificate,
  ) {}

  static fromPemChain(pems: string[]): PckCertificateChain {
    if (pems.length < 2) {
      throw new AttestationError(
        `Invalid PCK certificate chain: expected at least 2 certificates, got ${pems.length}`
      );
    }

    const trustedRoot = X509Certificate.parse(INTEL_SGX_ROOT_CA_PEM);

    let pckLeaf: X509Certificate;
    let intermediate: X509Certificate;
    let root: X509Certificate;

    try {
      pckLeaf = X509Certificate.parse(pems[0]);
      intermediate = X509Certificate.parse(pems[1]);
      root = pems.length >= 3
        ? X509Certificate.parse(pems[2])
        : trustedRoot;
    } catch (e) {
      throw new AttestationError('Failed to parse PCK certificate chain', { cause: e as Error });
    }

    return new PckCertificateChain(pckLeaf, intermediate, root, trustedRoot);
  }

  async verifyChain(): Promise<void> {
    try {
      const now = new Date();
      if (!this.pckLeaf.validForDate(now)) {
        throw new AttestationError('PCK leaf certificate has expired or is not yet valid');
      }
      if (!this.intermediate.validForDate(now)) {
        throw new AttestationError('PCK intermediate CA certificate has expired or is not yet valid');
      }
      if (!this.trustedRoot.validForDate(now)) {
        throw new AttestationError('Intel SGX Root CA certificate has expired or is not yet valid');
      }

      // Verify BasicConstraints CA=True on non-leaf certificates
      if (!this.root.isCA) {
        throw new AttestationError('PCK root certificate does not have BasicConstraints CA=True');
      }
      if (!this.intermediate.isCA) {
        throw new AttestationError('PCK intermediate CA certificate does not have BasicConstraints CA=True');
      }

      // Verify: root is self-signed (or matches trusted root)
      const rootVerified = await this.root.verify();
      if (!rootVerified) {
        throw new AttestationError('PCK root certificate is not properly self-signed');
      }

      // Verify root matches the hardcoded Intel SGX Root CA
      // Compare the public key bytes to ensure the chain terminates at the trusted root
      const rootKeyDer = this.root.publicKey;
      const trustedKeyDer = this.trustedRoot.publicKey;
      if (rootKeyDer.length !== trustedKeyDer.length ||
          !rootKeyDer.every((b: number, i: number) => b === trustedKeyDer[i])) {
        throw new AttestationError(
          'PCK root certificate public key does not match the hardcoded Intel SGX Root CA'
        );
      }

      // Verify intermediate signed by root
      const intermediateSignedByRoot = await this.intermediate.verify(this.root);
      if (!intermediateSignedByRoot) {
        throw new AttestationError('PCK intermediate CA certificate is not signed by root');
      }

      // Verify leaf signed by intermediate
      const leafSignedByIntermediate = await this.pckLeaf.verify(this.intermediate);
      if (!leafSignedByIntermediate) {
        throw new AttestationError('PCK leaf certificate is not signed by intermediate CA');
      }
    } catch (e) {
      wrapOrThrow(e, AttestationError, 'Intel PCK certificate chain verification failed');
    }
  }

  checkRevocation(revokedSerials: Uint8Array[]): void {
    const leafSerial = this.pckLeaf.serialNumber;
    const intermediateSerial = this.intermediate.serialNumber;
    for (const revoked of revokedSerials) {
      if (uint8ArrayEqual(leafSerial, revoked)) {
        throw new AttestationError('PCK leaf certificate has been revoked');
      }
      if (uint8ArrayEqual(intermediateSerial, revoked)) {
        throw new AttestationError('PCK intermediate CA certificate has been revoked');
      }
    }
  }

  get pckPublicKey(): Promise<CryptoKey> {
    return this.pckLeaf.publicKeyObj;
  }
}
