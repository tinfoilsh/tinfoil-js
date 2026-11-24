# @tinfoilsh/verifier

Verifies Tinfoil attestation documents in TypeScript, on Node, Bun and in browsers: the enclave's hardware quote (AMD SEV-SNP or Intel TDX), the Sigstore provenance of the code and platform it runs, the freshness of those endorsements, and the policy that ties the quote's measurements to the release. The verifier opens no connections, keeps no state between calls, and uses WebCrypto only.

**Most users should use the main [`tinfoil`](https://www.npmjs.com/package/tinfoil) package instead.** Its clients fetch the document, run this verifier and bind every request to the verified enclave. Use this package directly for standalone verification, custom verification flows, or audit tooling. Coming from 1.x? See [Migrating from 1.x to 2.0](https://github.com/tinfoilsh/tinfoil-js/blob/main/MIGRATION.md).

## Installation

```bash
npm install @tinfoilsh/verifier
```

## Quick Start

```typescript
import { Verifier, randomNonce, toHex } from "@tinfoilsh/verifier";

// Embedded production trust roots and signing keys, 7-day freshness bound.
const verifier = await Verifier.create();

// The enclave serves its document for a nonce you choose, which the
// attestation endpoint takes as lowercase hex in the query string.
const nonce = randomNonce();
const response = await fetch(`https://inference.tinfoil.sh/.well-known/tinfoil-attestation?nonce=${toHex(nonce)}`);
const document = new Uint8Array(await response.arrayBuffer());

const report = await verifier.verifyV3(document, nonce, { repo: "tinfoilsh/confidential-model-router", project: "tinfoilsh/confidential-model-router" });
const facts = report.verifiedFacts!; // set on every report that verifyV3 returns

facts.codeDigest;         // the verified release
facts.enclaveMeasurement; // the quote's authenticated registers
facts.tlsPublicKeyFP;     // the endorsed TLS key (SPKI SHA-256), if any
facts.hpkePublicKey;      // the endorsed HPKE key, if any
facts.freshnessExpiresAt; // when a cached verification stops authorizing requests
```

`verifyV3` samples the clock once and judges every time-bound check at that instant; `verifyV3At(document, nonce, pin, when)` uses `when` instead. `pin` is `{ repo }` for a GitHub repository (`owner/name[@tag][@sha256:digest]`), `{ project }` for a config registry project (`org/project[@revision][@sha256:digest]`), or both to accept either; neither is satisfied by the other's collateral. An empty pin is a `UsageError` unless the verifier configures its own config trust. `parseReference` validates a reference, and `checkPinVerifiability(pin)` rejects a pin the verifier could never accept, without a document.

`Verifier.create(config?, policy?)` takes two values. `config` names who vouches for the config that an enclave runs, as one variant told apart by `kind`; undefined selects Tinfoil's public registry:

- `{ kind: "registries", ids }` accepts configs that exactly these registries certify; list `PUBLIC_REGISTRY_ID` among them, `[PUBLIC_REGISTRY_ID, ...mine]`, to keep accepting the public one.
- `{ kind: "configSigningKeys", keys }` accepts configs that these PEM-encoded P-256 keys sign.
- `{ kind: "configAuthorizer", authorize }` lets the caller authorize the config itself.
- `{ kind: "embeddedConfig", bytes, name? }` and `{ kind: "embeddedConfigReference", digest, runtime, name? }` trust an exact config that the caller supplies, by its bytes or, when the bytes are not disclosed, by its SHA-256 and the runtime release that it pins.

`policy` is plain data, and every field is optional: `pinnedRegisters` must match the enclave's registers, `freshnessMaxAgeMs` bounds witness age, and `artifacts` selects how the runtime and platform artifacts are trusted, either `{ kind: "endorsedArtifacts", freshnessKeys? }` (the default, with keys that replace Tinfoil's artifact approval keys) or `{ kind: "embeddedArtifacts", runtime?, platform?, freshnessKeys? }` with caller-trusted artifacts. `embeddedArtifacts` replaces the endorsement only of the artifacts that it supplies: one that it leaves out is still endorsed, its freshness approval signed by `freshnessKeys` or Tinfoil's keys. Every choice other than the defaults requires attestation-collaterals/v3. An invalid field, or an unknown `kind`, is a `UsageError`.

```typescript
const verifier = await Verifier.create({ kind: "registries", ids: [PUBLIC_REGISTRY_ID, myRegistryID] }, { freshnessMaxAgeMs: 24 * 60 * 60 * 1000 });
```

### Verification reports

`verifyV3` returns a `VerificationReport`: one step for each layer (`envelope`, `provenance`, `quote` and `policy`, in that order), each `passed`, `failed`, `skipped` or `not_run`, with a diagnostic `message` for a failed or skipped step; the facts that the steps established; and `metadata`, the verifier's name and version and the instant that the document was appraised at. Provenance is `skipped` only when the verifier embeds the config, the runtime and the platform, so that there is no endorsement to authenticate. A report authorizes nothing by itself: only the keys in its verified facts may be bound to.

- **Accepted:** `verifyV3` resolves to the report, whose `verifiedFacts` are set and none of whose steps failed.
- **Rejected:** `verifyV3` rejects with a `VerificationError` whose `report` has the step that failed, whose layer is the error's, and `partialFacts` instead of verified facts. `report.failedStep()` returns that step.
- **Misused:** a `UsageError` carries no report, because it reports a mistake in the caller's code rather than a rejected document.

`VerifiedFacts` is a frozen object of `readonly` properties: `codeDigest`, `codeTag`, `configRepo`, `codeMeasurement` (the registers the release fixes), `enclaveMeasurement`, `cryptoMaterial` and `cryptoMaterialData(id, format)` for every endorsed key, and `config`, `runtime` and `platform` for what a config-based verification accepted and where each reference came from.

`PartialFacts` hold what the steps before a failure established, and each fact is set only once the step that establishes it passed. `expected`, set once provenance passed or was skipped, holds the accepted reference values: `configRepo`, `artifact`, `config` and `platform` as verified facts would report them, `codeMeasurement`, the registers that the release fixes in the layout of the platform that the document's CPU evidence names, and `measurement`, every register that the quote had to attest, set once the policy step resolved it. `measured`, set once the envelope passed, holds `cpu.measurement`, the registers that the hardware measured, set only once the quote authenticated, and `tlsPublicKeyFP` and `hpkePublicKeyFP`, the fingerprints of the keys that the document endorses. Only the policy step binds those keys to the enclave, so in a failed report they are the document's claim, and must be shown as unverified. Partial facts hold the HPKE key only as a fingerprint, the lowercase-hex SHA-256 of its bytes that `hpkePublicKeyFP(key)` computes. A measurement mismatch shows `expected.measurement` next to `measured.cpu.measurement`, register by register.

A report and everything in it are frozen, except register bytes and `Date` values, which can't be frozen and must not be mutated; `report.clone()` gives a copy that shares neither. Its data properties survive a structured clone, such as `postMessage`, and `JSON.stringify(report)` (or `toJSON()`) gives the same data as plain JSON, with registers as lowercase hex and times as ISO 8601 strings.

### Errors

Every error is a `VerifyError`, except from the hex helpers: `fromHex` verifies nothing, so it throws a plain `Error` for anything but lowercase hex of even length, the form `toHex` writes. A `UsageError` means the verifier was built or called with invalid inputs, so retrying won't help. A `VerificationError` means the document must not be trusted; its `report` shows what the verification established (see above), and its `layer` names the check that failed: `envelope` (document shape and nonce binding), `provenance` (code, config and platform endorsements and their freshness), `quote` (the hardware quote) or `policy` (the measurements against the release). Those are the layers today; a later version may add one, so treat a `layer` you don't recognize as a rejection at a stage you have no name for. The verifier fails closed: an internal failure inside a layer (a bug, an exhausted resource) is reported as a `VerificationError` at that layer with the underlying error as `cause`, so an unfamiliar message at a layer may be the verifier itself failing rather than the document; inspect `cause` before treating it as a verdict on the document.

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
