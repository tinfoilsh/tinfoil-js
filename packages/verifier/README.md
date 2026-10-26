# @tinfoilsh/verifier

Offline, browser-compatible TypeScript library for verifying v3 AMD SEV-SNP and Intel TDX attestation documents, endorsed artifacts, and freshness.

**Most users should use the main [`tinfoil`](https://www.npmjs.com/package/tinfoil) package instead.** It includes this verifier and runs it automatically. Use this package directly for standalone verification, custom verification flows, or audit tooling.

## Installation

```bash
npm install @tinfoilsh/verifier
```

## Quick Start

```typescript
import {
  Verifier,
  randomNonce,
  fetchAttestationDocument,
  UsageError,
  VerificationError,
} from '@tinfoilsh/verifier';

const verifier = new Verifier();
const nonce = randomNonce();
// Acquisition returns untrusted bytes and enforces a 32 MiB response limit.
const bytes = await fetchAttestationDocument('https://enclave.example.com', nonce, {
  signal: AbortSignal.timeout(30_000),
});

try {
  const verified = await verifier.verifyDocumentV3(
    bytes,
    nonce,
    'tinfoilsh/confidential-model-router',
  );
  console.log(verified.enclaveMeasurement);
  console.log(verified.tlsPublicKeyFingerprint());
  console.log(verified.hpkePublicKey());
  console.log(verified.freshnessExpiresAt);
} catch (error) {
  if (error instanceof UsageError) {
    // Invalid caller input or verifier options.
    console.error(error.message);
  } else if (error instanceof VerificationError) {
    // Attestation rejected at envelope, provenance, quote, or policy validation.
    console.error(error.layer, error.message);
  } else {
    throw error;
  }
}
```

Generate a fresh nonce for each acquisition and pass the same nonce to verification. `Verifier` accepts policy options such as `freshnessMaxAgeMs` and `pinnedRegisters`; the endpoint and trusted repository are supplied per operation. Verification performs no network requests: the v3 document carries its collateral. Acquisition failures are separate from attestation rejection.

`verifyDocumentV3(bytes, nonce, identity)` is also exported as a convenience function using default policy. For archived evidence, use `verifyDocumentV3At(bytes, nonce, identity, time)` (also available on `Verifier`) with the original challenge nonce and an explicit `Date`. Historical verification does not authorize a current connection.

A successful `Verification` provides immutable authenticated facts, including `config`, `runtime`, `platform`, and `metadata`. Obtaining a TLS fingerprint does not pin a connection: a custom transport must compare it with the live peer certificate's SPKI on every new TLS connection, in addition to normal hostname and certificate validation. HPKE transports must bind encryption to the verified HPKE key, and live clients must refresh before the authenticated freshness deadline.

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
