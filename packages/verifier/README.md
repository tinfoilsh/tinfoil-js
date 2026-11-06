# @tinfoilsh/verifier

Verifies Tinfoil attestation documents in TypeScript, on Node, Bun and in browsers: the enclave's hardware quote (AMD SEV-SNP or Intel TDX), the Sigstore provenance of the code and platform it runs, the freshness of those endorsements, and the policy that ties the quote's measurements to the release. The verifier opens no connections, keeps no state between calls, and uses WebCrypto only.

**Most users should use the main [`tinfoil`](https://www.npmjs.com/package/tinfoil) package instead.** Its clients fetch the document, run this verifier and bind every request to the verified enclave. Use this package directly for standalone verification, custom verification flows, or audit tooling. Coming from 1.x? See [Migrating from 1.x to 2.0](https://github.com/tinfoilsh/tinfoil-js/blob/main/MIGRATION.md).

## Installation

```bash
npm install @tinfoilsh/verifier
```

## Quick Start

```typescript
import { Verifier, randomNonce } from "@tinfoilsh/verifier";

// Embedded production trust roots and signing keys, 7-day freshness bound.
const verifier = await Verifier.create();

// The enclave serves its document for a nonce you choose.
const nonce = randomNonce();
const hex = Array.from(nonce, (b) => b.toString(16).padStart(2, "0")).join("");
const response = await fetch(`https://inference.tinfoil.sh/.well-known/tinfoil-attestation?nonce=${hex}`);
const document = new Uint8Array(await response.arrayBuffer());

const verification = await verifier.verifyV3(document, nonce, "tinfoilsh/confidential-model-router");

verification.codeDigest;         // the verified release
verification.enclaveMeasurement; // the quote's authenticated registers
verification.tlsPublicKeyFP;     // the endorsed TLS key (SPKI SHA-256), if any
verification.hpkePublicKey;      // the endorsed HPKE key, if any
verification.freshnessExpiresAt; // when a cached verification stops authorizing requests
```

`verifyV3` samples the clock once and judges every time-bound check at that instant; `verifyV3At(document, nonce, repo, when)` uses `when` instead. The `repo` pin is `owner/name[@tag][@sha256:digest]` (`parseReference` validates one), and `checkRepoVerifiability(repo)` rejects a pin the verifier could never accept, without a document.

`Verifier.create(options)` configures the policy: `pinnedRegisters` must match the enclave's registers, `freshnessMaxAgeMs` bounds witness age, `configSigningKeys` and `freshnessSigningKeys` replace the public trust in the config and approval signers, `configRegistryIDs` names the registries whose certified config approvals are accepted instead of the public registry alone (`additionalConfigRegistryIDs` accepts them alongside it), `configAuthorizer` lets the caller authorize the config itself, and `embeddedReferences` supplies caller-trusted reference values for the config (its bytes, or a `configReference` with its digest and runtime pin when the bytes are not disclosed), runtime or platform. An option that cannot be honoured is a `UsageError`.

A `Verification` is a frozen object of `readonly` properties: `codeDigest`, `codeTag`, `configRepo`, `codeMeasurement` (the registers the release fixes), `enclaveMeasurement`, `cryptoMaterial` and `cryptoMaterialData(id, format)` for every endorsed key, `config`, `runtime` and `platform` for what a config-based verification accepted and where each reference came from, and `metadata` for the verifier's name and version and when it ran. Register bytes and `Date` values are shared, not copied, and must not be mutated. `JSON.stringify(verification)` (or `toJSON()`) gives the same facts as plain JSON, with registers as lowercase hex and times as ISO 8601 strings.

### Errors

Every error is a `VerifyError`. A `UsageError` means the verifier was built or called with invalid inputs, so retrying won't help. A `VerificationError` means the document must not be trusted; its `layer` names the check that failed: `envelope` (document shape and nonce binding), `provenance` (code, config and platform endorsements and their freshness), `quote` (the hardware quote) or `policy` (the measurements against the release). Those are the layers today; a later version may add one, so treat a `layer` you don't recognize as a rejection at a stage you have no name for. The verifier fails closed: an internal failure inside a layer (a bug, an exhausted resource) is reported as a `VerificationError` at that layer with the underlying error as `cause`, so an unfamiliar message at a layer may be the verifier itself failing rather than the document; inspect `cause` before treating it as a verdict on the document.

### Pinning

Reading `tlsPublicKeyFP` pins nothing: a transport must compare it with the live peer certificate's SPKI fingerprint on every new TLS connection, in addition to normal hostname and certificate validation; `certPubkeyFP(certDer)` computes the same form from a DER certificate. Likewise `hpkePublicKey` only identifies the key request bodies must be sealed to.

See [Attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture) and [Verification in Tinfoil](https://docs.tinfoil.sh/verification/verification-in-tinfoil) for what gets verified.

## Development

```bash
npm run build
npm test
npm run test:browser
npm run test:conformance   # the shared tinfoil-conformance fixtures; set TINFOIL_CONFORMANCE_FIXTURES to its vectors/v3
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
