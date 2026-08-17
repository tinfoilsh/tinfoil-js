# v3 port: tinfoil-go `feat/v3` → tinfoil-js, 1:1

Reference implementation: `/Users/g/tinfoil/tinfoil-go/verifier/` on branch
`feat/v3-conformance-harness` (= `feat/v3` + tag-gated conformance seams).
Port function-by-function: same names (camelCased), same check order, same
error conditions. Comments: only where Go has one worth keeping; succinct.

Acceptance bar per module: its stage's fixtures in
`/Users/g/tinfoil/tinfoil-conformance/vectors/v3/` pass via
`tools/run_adapter.py` (same verdict, same reject layer, same accept facts).

## Module map and ownership (one agent per row; do not edit others' files)

| owner | files (packages/verifier/src/v3/) | Go source |
|---|---|---|
| foundation | `errors.ts`, `bytes.ts`, `envelope.ts`, `measurement.ts`, `policy.ts`, `index.ts` + `packages/conformance/` CLI skeleton | `verifier/envelope/envelope.go`, `verifier/measurement/`, `verifier/policy/`, `verifier/internal/strictjson` |
| provenance | `provenance/provenance.ts`, `provenance/freshness.ts`, `provenance/bundle-format.ts` | `verifier/provenance/*.go` |
| sev | `sev/*.ts` | `verifier/quote/sev/*.go` (+ go-sev-guest semantics it delegates to) |
| tdx | `tdx/*.ts` | `verifier/quote/tdx/*.go` (+ go-tdx-guest semantics it delegates to) |
| integration | `quote.ts`, `client.ts`, final `packages/conformance/src/cli.ts` wiring | `verifier/quote/quote.go`, `verifier/client/verify.go`, `verifier/conformance/conformance.go` |

Embedded production roots are already at `embedded/roots.ts`
(`trustedRootJSON`, `genoaCertChainPEM`, `sgxRootCAPEM`) — byte-identical to
Go's `go:embed` files. Default to them when no override is given.

## Fixed interfaces (code against these exactly)

```ts
// measurement.ts
export type PredicateType = string;
export const SevGuestV2 = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
export const TdxGuestV2 = "https://tinfoil.sh/predicate/tdx-guest/v2";
export const SnpTdxMultiPlatformV1 = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";
export interface Measurement { type: PredicateType; registers: string[] }

// envelope.ts — strict parsing (unknown fields reject, exact types), Go check order
export const NonceSize = 32;
export interface Document { /* mirrors Go envelope.Document */ }
export function parseDocument(docBytes: Uint8Array): Document;               // envelope.Parse
export function check(docBytes: Uint8Array, expectedNonce: Uint8Array):
  { doc: Document; reportData: Uint8Array /* 64 bytes */ };                  // envelope.Check
export interface SigstoreCollateral { repo: string; tag: string; digest: string; sigstoreBundle: Uint8Array }
export function referenceValuesCollateral(doc: Document, format: string): SigstoreCollateral;
export function freshnessCollateral(doc: Document, id: string): { sigstoreBundle: Uint8Array };
export function endorsementCollateral(doc: Document, format: string, subject: string): { id: string; data: unknown } | undefined;
export function cryptoMaterialItems(doc: Document): { id: string; format: string; data: string }[];

// policy.ts — fail-closed artifact parse (unknown member anywhere rejects)
export interface Artifact { /* measurements, machines, policies — mirror Go */ }
export function parseArtifact(artifactJSON: Uint8Array): Artifact;

// provenance/provenance.ts
export interface AuthenticatedArtifact { repo: string; tag: string; commit: string; subjectName: string; digest: string }
export interface Shape { cpus: number; memoryMB: number; gpus: number; disks: number }
export interface Code extends AuthenticatedArtifact { measurement: Measurement; shape: Shape }
export interface PlatformEndorsements extends AuthenticatedArtifact { artifact: Artifact }
export interface ProvenanceOpts { trustRootJSON?: Uint8Array }               // default: embedded
export function authenticateCode(bundleJSON: Uint8Array, repo: string, tag: string, hexDigest: string, opts?: ProvenanceOpts): Promise<Code>;
export function authenticatePlatformEndorsements(bundleJSON: Uint8Array, repo: string, tag: string, hexDigest: string, opts?: ProvenanceOpts): Promise<PlatformEndorsements>;
// provenance/freshness.ts
export function authenticateFreshness(bundleJSON: Uint8Array, expected: AuthenticatedArtifact, now: Date, opts?: ProvenanceOpts): Promise<Date>;

// sev/  and  tdx/
export interface QuoteOpts { rootPEM?: string; now?: Date }                  // default: embedded root, current time
export interface SevQuote { identity: string; measurement: Measurement; report: SevReport }
export function sevAuthenticate(doc: Document, opts?: QuoteOpts): Promise<SevQuote>;
export interface TdxQuote { identity: string; measurement: Measurement; tcbEvaluationDataNumber: number; body: TdxBody }
export function tdxAuthenticate(doc: Document, opts?: QuoteOpts): Promise<TdxQuote>;
// each also exports its policy-comparison step, mirroring Go's expectations.go:
export function sevValidate(q: SevQuote, endorsed: SevPolicy, code: Measurement, shape: Shape, reportData: Uint8Array, identityPolicy: ...): void; // throws on mismatch
// (exact per-field semantics: read Go expectations.go — go-sev-guest / go-tdx-guest options)

// quote.ts (integration)
export interface Authenticated { platform: "sev-snp" | "tdx"; identity: string; measurement: Measurement; sev?: SevQuote; tdx?: TdxQuote }
export function quoteAuthenticate(doc: Document, opts?: { amdRootPEM?: string; intelRootPEM?: string; now?: Date }): Promise<Authenticated>;
export function assembleAndValidate(endorsements: Artifact, code: Measurement, shape: Shape, reportData: Uint8Array, auth: Authenticated): void;

// client.ts (integration) — mirrors client.VerifyDocumentV3 + reference values incl. freshness
export interface VerifyOpts { sigstoreRootJSON?: Uint8Array; amdRootPEM?: string; intelRootPEM?: string; verificationTime?: Date }
export function verifyDocumentV3(docBytes: Uint8Array, nonce: Uint8Array, repo: string, opts?: VerifyOpts): Promise<VerifiedDocumentV3>;
```

Error model: every rejection throws `VerificationError(layer, message)` with
`layer` ∈ ENVELOPE_REJECTED | PROVENANCE_REJECTED | QUOTE_REJECTED |
POLICY_REJECTED (defined in `errors.ts` by foundation). The adapter maps a
thrown layer to the wire `rejection.code`; MALFORMED_INPUT is adapter-level.

## Adapter wire contract (packages/conformance)
`node packages/conformance/dist/cli.js <stage>`; Input JSON on stdin, Output
JSON on stdout, exit 0 accepted / 10 rejected / 20 unsupported / 30 malformed.
Stages + Input/Output/codes: `tinfoil-conformance/docs/V3_CONFORMANCE_HARNESS_SPEC.md`
and `schemas/v3/*.json`. `verification_time_unix` pins BOTH the quote-layer
clock and the freshness appraisal time. Empty root fields ⇒ embedded roots.
Accept outputs must include code_digest, code_measurement, enclave_measurement,
tls_public_key_fp, hpke_public_key.

## Environment
Node ≥ 22 (node:crypto, X509Certificate, webcrypto), TypeScript, vitest.
Runtime target for the adapter is Node; keep browser-compatible code where
free, but never at the cost of 1:1 semantics.
