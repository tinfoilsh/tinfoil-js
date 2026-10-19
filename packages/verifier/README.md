# @tinfoilsh/verifier

Browser-compatible TypeScript library for verifying AMD SEV-SNP attestation reports and Sigstore code provenance.

**Most users should use the main [`tinfoil`](https://www.npmjs.com/package/tinfoil) package instead.** It includes this verifier and runs it automatically. Use this package directly for standalone verification, custom verification flows, or audit tooling.

## Installation

```bash
npm install @tinfoilsh/verifier
```

## Quick Start

```typescript
import { Verifier } from '@tinfoilsh/verifier';

const verifier = new Verifier({
  serverURL: 'https://enclave.example.com',
  configRepo: 'tinfoilsh/confidential-model-router',
});
const attestation = await verifier.verify();

console.log(attestation.measurement);
console.log(attestation.tlsPublicKeyFingerprint);
console.log(attestation.hpkePublicKey);

// Per-step results and measurements
const doc = verifier.getVerificationDocument();
console.log(doc?.securityVerified);
```

`verifyBundle(bundle)` verifies an attestation bundle you already hold. Failures throw `ConfigurationError`, `FetchError`, or `AttestationError`.

Obtaining `tlsPublicKeyFingerprint` does not pin anything: a custom transport must compare it with the live peer certificate's SPKI on every new TLS connection, in addition to normal hostname and certificate validation.

Release metadata and attestation bundles are fetched through Tinfoil-hosted GitHub proxy endpoints, so verification fails in environments that cannot reach them.

See [Attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture) and [Verification in Tinfoil](https://docs.tinfoil.sh/verification/verification-in-tinfoil) for what gets verified.

## Development

```bash
npm run build
npm test
npm run test:browser
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
