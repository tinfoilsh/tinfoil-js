# @tinfoilsh/verifier

Browser-compatible TypeScript library for verifying AMD SEV-SNP attestation reports and Sigstore code provenance.

## When to Use This Package

**Most users should use the main `tinfoil` package instead.** It includes this verifier and handles verification automatically.

Use `@tinfoilsh/verifier` directly when you need:

- **Standalone verification** — Verify enclaves without making API requests
- **Custom verification flows** — Verify before creating clients, or verify arbitrary enclaves
- **Lighter dependency** — If you only need verification, not the full SDK
- **Audit/compliance tooling** — Build tools that verify enclaves independently

## Installation

```bash
npm install @tinfoilsh/verifier
```

## Quick Start

```typescript
import { Verifier } from '@tinfoilsh/verifier';

const verifier = new Verifier({ serverURL: 'https://enclave.example.com' });
const attestation = await verifier.verify();

console.log(attestation.measurement);
console.log(attestation.tlsPublicKeyFingerprint);
console.log(attestation.hpkePublicKey);
```

## Verifying a Pre-Fetched Bundle

If you already have a complete attestation bundle (for example, fetched via the
`tinfoil` SDK’s `fetchAttestationBundle()` helper), you can verify it directly:

```typescript
import { Verifier } from '@tinfoilsh/verifier';
import type { AttestationBundle } from '@tinfoilsh/verifier';

const verifier = new Verifier({
  serverURL: 'https://enclave.example.com',
  configRepo: 'tinfoilsh/confidential-model-router',
});

const bundle: AttestationBundle = /* fetch bundle from your source */;
await verifier.verifyBundle(bundle);

const doc = verifier.getVerificationDocument();
console.log(doc.securityVerified);
```

## Error Handling

For callers that want structured error handling, these errors are part of the public API:

- `AttestationError` (and `FormatMismatchError`, `MeasurementMismatchError`) — measurement/format validation
- `CertificateVerificationError` — enclave TLS certificate SAN validation for HPKE key + attestation hash

## Inspecting Verification Results

The verification document contains detailed information about each step:

```typescript
const doc = verifier.getVerificationDocument();

// Overall result
console.log(doc.securityVerified); // true if all checks passed

// Individual steps
console.log(doc.steps.fetchDigest);       // Fetched release digest from GitHub
console.log(doc.steps.verifyCode);        // Verified code via Sigstore
console.log(doc.steps.verifyEnclave);     // Verified AMD SEV-SNP attestation
console.log(doc.steps.compareMeasurements); // Compared code vs enclave measurements

// Measurements
console.log(doc.codeFingerprint);     // Expected measurement from signed release
console.log(doc.enclaveFingerprint);  // Actual measurement from enclave
```

## What Gets Verified

The `Verifier` performs a multi-step verification:

1. **Fetch Release Digest** — Gets the expected code digest from the signed GitHub release
2. **Verify Code Provenance** — Uses Sigstore (Fulcio + Rekor) to verify the release signature
3. **Verify Enclave Attestation** — Validates the AMD SEV-SNP attestation report and VCEK certificate chain
4. **Compare Measurements** — Ensures the enclave is running the exact code from the signed release

## Features

- AMD SEV-SNP attestation verification (VCEK certificate chain validation)
- Sigstore code provenance verification (Fulcio + Rekor)
- TUF-based trusted root updates
- Works in Node.js and browsers (uses Web Crypto API)

## GitHub Proxy Dependency

This package fetches GitHub release metadata and attestation bundles via Tinfoil-hosted
GitHub proxy endpoints (to avoid rate-limits/CORS issues). If your environment cannot
reach these endpoints, verification that depends on GitHub release attestations will fail.

## Relationship to `tinfoil` Package

The main [`tinfoil`](https://www.npmjs.com/package/tinfoil) package includes this verifier and uses it automatically:

```typescript
// tinfoil package — verification happens automatically
import { TinfoilAI } from 'tinfoil';
const client = new TinfoilAI({ apiKey: 'key' });
// Verification runs when you make your first request

// You can also access the verification document
const doc = await client.getVerificationDocument();
```

Use `@tinfoilsh/verifier` directly only if you have specific needs listed in "When to Use This Package" above.

## Learn More

- [How It Works](https://docs.tinfoil.sh/cc/how-it-works) — Confidential computing overview
- [Verifiability](https://docs.tinfoil.sh/cc/verifiability) — How attestation proves security
- [Attestation Architecture](https://docs.tinfoil.sh/verification/attestation-architecture) — Technical deep-dive
- [Overview of Verification](https://docs.tinfoil.sh/verification/how-to-verify) — Verification process

## Development

```bash
npm run build
npm test
npm run test:browser
```
