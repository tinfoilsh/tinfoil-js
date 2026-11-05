# Migrating from 1.x to 2.0

2.0 replaces the verification protocol and the client API of both packages. Verification now appraises one attestation document the enclave serves for a caller-chosen nonce (hardware quote, code and platform provenance, freshness and policy together), and every client verifies before it exists. Nothing from 1.x is aliased; the tables map each removed name to its replacement.

## `tinfoil`

| 1.x | 2.0 |
|---|---|
| `new TinfoilAI({ apiKey })`, lazy with `await client.ready()` | `await createClient({ apiKey })`: a `TinfoilClient` (an `OpenAI` subclass) verified before it is returned. A browser page passes `bearerToken` instead of `apiKey`. |
| `new SecureClient(options)` with `ready()`, `fetch`, `reset()`, `getBaseURL()`, `getEnclaveURL()` | `await RouterHTTPClient.create(options)` (the discovered router) or `await EnclaveHTTPClient.create(host, repo, options)` (one enclave), with `fetch` (absolute URLs), `baseURL()`, `enclave()`, `repo()`, `current()`, `ensureVerified()` and `reverify()`. `RouterOpenAIClient.create(options, openaiOptions)` and `EnclaveOpenAIClient.create(host, repo, options, openaiOptions)` wrap them as OpenAI clients. |
| `enclaveURL` and `configRepo` options | `EnclaveHTTPClient.create(host, repo)` / `EnclaveOpenAIClient.create(host, repo)`: the enclave is named up front, not chosen later |
| `transport` option (default `"ehbp"` everywhere) | `transportMode`: `"tls"` by default on Node and Bun (the connection is pinned to the attested key), `"ehbp"` by default and alone in browsers. Pass `transportMode: "ehbp"` to keep sealed request bodies on Node. |
| `baseURL` as a proxy | `baseURL` still names a proxy and requires `"ehbp"`; it must be HTTPS (`http://` only to localhost or a loopback IP address), and requests carry `X-Tinfoil-Enclave-Url` |
| `createTinfoilAI(apiKey, options)` from `tinfoil` | `await createTinfoil({ apiKey \| bearerToken, ...clientOptions, enclave? })` from `tinfoil/ai-sdk`, its own entry so the AI SDK stays out of bundles that don't use it; `provider.httpClient()` is the attested client underneath |
| `TINFOIL_API_KEY` read when `apiKey` was omitted | no environment defaults: pass the credential |
| `attestationBundleURL`, `fetchAttestationBundle`, `fetchRouter` | removed: the document comes from the enclave itself, and router discovery is built into the router clients (the first router that verifies, falling back to `inference.tinfoil.sh`) |
| `getVerificationDocument()`, `VerificationDocument`, `VerificationStepState` | `ensureVerified()` returns a currently valid `Verification` with every fact, verifying again if needed; `current()` is only the last successful one, unchecked, and may be undefined or expired. A verification failure is an `AttestationError` wrapping a `VerificationError` whose `layer` names the failed check |
| `Verifier`, `assembleAttestationBundle` and the attestation types re-exported from `tinfoil` | import the verifier from `@tinfoilsh/verifier`; pass a `Verifier` through the `verifier` option to change the policy |
| `FetchError` | `NetworkError`. `TinfoilError`, `ConfigurationError` and `AttestationError` keep their names. |
| `client.realtime({ model, options })` | `await createRealtimeWebSocket(client, { model, wsOptions })` (Node only) |
| `secureClient.createWebSocket(path, options)`, `getPinnedWebSocketOptions()` | `await createWebSocket(client, path, options)`, `await pinnedWebSocketOptions(client)` |
| `new UnverifiedClient()` from `tinfoil/unsafe`, discovering a router | `await UnverifiedClient.create({ baseURL \| keyOrigin })` from `tinfoil/unsafe`: it never discovers a server, and is for development against a local server only |
| `createUnverifiedEncryptedBodyFetch` | removed: `UnverifiedClient.fetch` |
| `tinfoil/v3`, `tinfoil/v3/ai-sdk`, `tinfoil/v3/unsafe` (pre-release entries) | `tinfoil`, `tinfoil/ai-sdk`, `tinfoil/unsafe` |

Unchanged: `userCacheSecret` and the per-request `user_cache_secret` field, their resolution from `TINFOIL_USER_CACHE_SECRET` and `~/.tinfoil/user_cache_secret` for the router, the session recovery helpers (`sessionRecoveryToken(response)` replaces reading the token off a response), and the OpenAI types and errors re-exported from the root.

## `@tinfoilsh/verifier`

| 1.x | 2.0 |
|---|---|
| `new Verifier({ serverURL, configRepo })`, `verify()`, `verifyBundle(bundle)` | `await Verifier.create(options?)`, then `verifyV3(document, nonce, repo)` or `verifyV3At(document, nonce, repo, when)`. Fetching is the caller's job: `GET https://<host>/.well-known/tinfoil-attestation?nonce=<hex>` with a `randomNonce()`. |
| `verifyAttestation`, `assembleAttestationBundle`, `AttestationBundle`, `AttestationDocument`, `AttestationResponse` | removed: the collateral travels inside the document |
| `verifyCertificate`, `CertVerificationResult` (HPKE key and attestation hash in certificate SANs) | removed: channel keys are endorsed in the document's crypto material, read with `tlsPublicKeyFP()`, `hpkePublicKey()`, `cryptoMaterial()` and `cryptoMaterialData(id, format)` |
| `compareMeasurements`, `measurementFingerprint`, `hashAttestationDocument`, `PredicateType`, `AttestationMeasurement`, `HardwareMeasurement` | the `Measurement` and `Expected` types with `parseRegister`, `parseExpectedSevSnp`, `parseExpectedTdx`, `registerHex` and `formatMeasurement`; `codeMeasurement()` and `enclaveMeasurement()` on a `Verification`; `pinnedRegisters` on the verifier to require registers |
| `getVerificationDocument()`, `VerificationDocument`, `VerificationStepState`, `cloneVerificationDocument`, `VERIFICATION_DOCUMENT_SCHEMA_VERSION` | removed: a `Verification` holds every fact, and a `VerificationError` carries its `layer` |
| `TinfoilError`, `ConfigurationError`, `FetchError`, `AttestationError` | `VerifyError` with `UsageError` (invalid inputs) and `VerificationError` (the document must not be trusted); the `tinfoil` package keeps its own error classes |
| `VERIFIER_NAME`, `VERIFIER_VERSION` | `verification.metadata.verifier` |
| `@tinfoilsh/verifier/v3` (pre-release entry) | the package root |
