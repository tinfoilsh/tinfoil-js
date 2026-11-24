# Tinfoil TypeScript Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-js/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-js/actions)
[![NPM version](https://img.shields.io/npm/v/tinfoil.svg)](https://npmjs.org/package/tinfoil)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/javascript-sdk)

A TypeScript client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Node client](https://github.com/openai/openai-node) with the same API. A client verifies the enclave's attestation before it is returned, and every request it sends is bound to the verified enclave: on Node and Bun the TLS connection is pinned to the attested key, and in browsers the request body is encrypted to the attested key with [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it. Works in Node (22.23.4+, 24.22.1+, or 26.12.1+), browsers, Electron, and Bun (1.4.0+ for the pinned TLS connection; see below), and supports the [Vercel AI SDK](https://sdk.vercel.ai/).

## Installation

```bash
npm install tinfoil@next
```

This README describes the 2.0 API, which is in prerelease, so it is published under the `next` tag. A plain `npm install tinfoil` still installs 1.x, whose API is documented in the [v1.4.0 README](https://github.com/tinfoilsh/tinfoil-js/blob/v1.4.0/README.md).

What to install depends on the entry point that you import:

| Entry point | Install |
|---|---|
| `tinfoil` (the attested HTTP clients and pinned WebSockets) and `tinfoil/unsafe` | `npm install tinfoil@next` |
| `tinfoil/openai` (the OpenAI client) | `npm install tinfoil@next openai` |
| `tinfoil/ai-sdk` (the Vercel AI SDK provider) | `npm install tinfoil@next ai @ai-sdk/openai-compatible` |

`openai`, `ai` and `@ai-sdk/openai-compatible` are optional peer dependencies, so installing `tinfoil` doesn't install them. `tinfoil/openai` imports `openai`, and `tinfoil/ai-sdk` imports `@ai-sdk/openai-compatible`; `ai` is what your own code calls with the provider. Importing either entry without its package fails with a module-not-found error that names the package.

## Quick Start

```typescript
import { createClient } from "tinfoil/openai";

// Discovers Tinfoil's inference router and verifies it before returning.
const client = await createClient({ apiKey: "<YOUR_API_KEY>" });

const completion = await client.chat.completions.create({
  messages: [{ role: "user", content: "Hello!" }],
  model: "gpt-oss-120b", // see https://docs.tinfoil.sh/models/chat
});
```

Router and enclave clients are async factories that verify before returning, and they verify again by themselves when the verification expires or the enclave's key changes. Gateway clients are async factories too, but verify a model's replica before its first request. `createClient` takes the OpenAI client's own options (except `baseURL` and `fetch`, which the attested transport owns) plus `bearerToken`, and returns an `OpenAIClient` with the same API as `new OpenAI(...)`, over a `RouterHTTPClient` created with the default options. For anything about the route itself, create the HTTP client and then an `OpenAIClient` over it:

```typescript
import { EnclaveHTTPClient, GatewayHTTPClient, RouterHTTPClient } from "tinfoil";
import { OpenAIClient } from "tinfoil/openai";

// One enclave, verified against a GitHub repository.
const enclave = await EnclaveHTTPClient.create("enclave.example.com", { kind: "repoPin", repo: "owner/name" });
const client = new OpenAIClient(enclave, {}, { apiKey: "<YOUR_API_KEY>" });

// The discovered router, with a verification policy of your own.
const router = await RouterHTTPClient.create({ policy: { freshnessMaxAgeMs: 24 * 60 * 60 * 1000 } });

// Tinfoil's gateway, which serves only the models that are pinned.
const gateway = await GatewayHTTPClient.create({
  modelPins: new Map([["deepseek-v4-1-flash", { repo: "tinfoilsh/confidential-deepseek-v4-1-flash" }]]),
});
```

`new OpenAIClient(httpClient, options?, openaiOptions?)` takes an `EnclaveHTTPClient`, `RouterHTTPClient` or `GatewayHTTPClient` and does no network I/O. It sets the OpenAI base URL itself, after your OpenAI options, so a `baseURL`, `OPENAI_BASE_URL` in the environment and `dataResidency` have no effect: the base URL is `options.apiPath` (`/v1/` by default) under the HTTP client's EHBP proxy or the enclave's origin, or the gateway's URL for a gateway client, which takes no `apiPath`. An HTTP client's `close()` releases its pooled connections and refuses further use, and both kinds of client support `await using` (an OpenAI client closes the HTTP client under it).

### Trust, policy and transport

`EnclaveHTTPClient.create(host, trust, options?)` takes a required `trust`, which names who vouches for the config that the enclave runs, as one object told apart by `kind`:

| `trust` | Accepts |
|---|---|
| `{ kind: "repoPin", repo }` | v2 collateral for a GitHub repository `owner/name[@tag][@sha256:digest]` |
| `{ kind: "projectPin", project, registryIDs? }` | v3 collateral for a config registry project `org/project[@revision][@sha256:digest]`, endorsed by the public registry, or by exactly the `registryIDs` given (list `PUBLIC_REGISTRY_ID` from `@tinfoilsh/verifier` to keep it); an empty list is a `ConfigurationError` |
| `{ kind: "signedBy", keys, project? }` | v3 configs that your PEM-encoded P-256 `keys` sign, optionally for one `project` |
| `{ kind: "authorizedBy", authorize }` | v3 configs that your `authorize` callback accepts |
| `{ kind: "embeddedConfig", bytes, name? }` | v3 collateral for exactly these config bytes |
| `{ kind: "eitherPin", repo, project }` | either of `repoPin` and `projectPin`, for the migration from v2 to v3 collateral |

The router's trust is fixed to its repository, and the gateway client takes `modelPins` instead, which maps each model name to a `tinfoilsh/` repository and an optional `policy`. A gateway client serves only the models that it has pins for, so it requires at least one pin, and a request or `ensureVerified` for any other model, including one that a later catalog adds, fails with a `ConfigurationError` without contacting a replica. Every HTTP client takes `policy`, the verifier's policy as plain data: `pinnedRegisters`, `freshnessMaxAgeMs` and `artifacts` (`{ kind: "endorsedArtifacts", freshnessKeys? }` or `{ kind: "embeddedArtifacts", runtime?, platform?, freshnessKeys? }`). The enclave and router clients take `transport`: `{ kind: "tls" }`, which pins each connection to the attested key, or `{ kind: "ehbp", proxyURL?, fetch? }`, which seals request and response bodies to the attested key so that they stay private through a proxy. The default depends on the platform:

| Platform | Default `transport` | `{ kind: "tls" }` |
|---|---|---|
| Node; Bun 1.4.0 or later; Deno 2.8.0 or later | TLS | accepted |
| Browsers; Bun before 1.4.0; Deno before 2.8.0 | EHBP | a `ConfigurationError`, since the platform can't pin the connection |

The trust, the policy and the options are checked before any network I/O: an invalid value, or an unknown `kind`, is a `ConfigurationError`.

Never put `apiKey` in browser code: the OpenAI clients and the AI SDK provider refuse it outside Node and Bun, `dangerouslyAllowBrowser` or not. Route browser requests through a [proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds the key, and authenticate the browser with a token of your own:

```typescript
import { RouterHTTPClient } from "tinfoil";
import { OpenAIClient } from "tinfoil/openai";

const router = await RouterHTTPClient.create({ transport: { kind: "ehbp", proxyURL: "https://proxy.example.com/" } });
const client = new OpenAIClient(router, {}, { bearerToken: "<SESSION_TOKEN>" });
```

### A page that contacts only your own origin

By default a client also fetches each enclave's attestation document directly from the enclave, and the router client fetches its list of candidate routers from `https://atc.tinfoil.sh/routers`. A page under a strict content security policy, or one that shouldn't reveal its users' IP addresses to enclaves, can send all three kinds of request to your own origin instead:

```typescript
import { attestationRelay, RouterHTTPClient, routerListRelay } from "tinfoil";
import { OpenAIClient } from "tinfoil/openai";

const router = await RouterHTTPClient.create({
  // Requests, with bodies sealed to the verified router's key.
  transport: { kind: "ehbp", proxyURL: "https://app.example/tinfoil/proxy" },
  // GET /tinfoil/.well-known/tinfoil-attestation?nonce=…&enclave=…
  fetchAttestation: attestationRelay("https://app.example/tinfoil"),
  // GET /tinfoil/routers
  fetchRouterList: routerListRelay("https://app.example/tinfoil"),
});
const client = new OpenAIClient(router, {}, { bearerToken: "<SESSION_TOKEN>" });
```

Your server implements three endpoints:

| Endpoint | Forwards to |
|---|---|
| The proxy (`proxyURL`) | The router named in the `X-Tinfoil-Enclave-Url` header, adding your API key. Forward only to the router hosts that you expect (those of Tinfoil's router list and `inference.tinfoil.sh`), since the header comes from the page and your API key goes wherever it names. Request and response bodies stay sealed |
| `{relay}/.well-known/tinfoil-attestation?nonce={hex}&enclave={host}` | `https://{host}/.well-known/tinfoil-attestation?nonce={hex}`, returning the body unchanged. Forward only to the enclave hosts that you expect, so that the relay isn't an open proxy |
| `{relay}/routers` | `https://atc.tinfoil.sh/routers`, returning the body unchanged |

The relays aren't trusted with anything: the client verifies every document that the relay returns, as it verifies one that it fetched itself: the document must answer the client's fresh nonce and pass the router's trust and policy. The router list only proposes candidates: discovery still verifies each one, and falls back to `inference.tinfoil.sh` when none passes. The proxy is trusted with what EHBP leaves unsealed: it sees the method, URL and headers of each request, including the page's bearer token, and adds your API key, so it is part of your own trusted server. One residual trust in the router list remains: a document doesn't name the host that served it, so the list's source is trusted not to name a host that relays another router's attestation, which would then receive the request headers, including the bearer token, although not the sealed bodies. Relay URLs follow the proxy URL's rules: HTTPS, or HTTP only to localhost or a loopback address, with no user information, query or fragment; `attestationRelay` and `routerListRelay` throw a `ConfigurationError` for a bad one when they are called. `fetchAttestation` and `fetchRouterList` also take a function of your own: `(host, nonce, { signal }) => Promise<Uint8Array>` and `({ signal }) => Promise<string[]>`. An `EnclaveHTTPClient` takes `fetchAttestation` too.

Browsers use the EHBP transport, the default and the only one available there. The package's type declarations are shared with the Node build, so a browser project type-checks a few names that throw a `ConfigurationError` when called: `createWebSocket` and `pinnedWebSocketOptions` (a verified WebSocket pins the server certificate, which browsers don't expose to scripts), `createRealtimeWebSocket` (a realtime session runs over such a WebSocket), and `transport: { kind: "tls" }` (the TLS transport pins the server certificate too; EHBP seals request and response bodies to the enclave's key instead).

Bun pins the TLS connection from Bun 1.4.0, the first release whose `fetch` checks the server certificate before it sends the request; on an older Bun the default transport is EHBP and `transport: { kind: "tls" }` is refused with a `ConfigurationError`. `createWebSocket` needs Bun 1.4.4 or later, the first release whose WebSocket runs the certificate check at all, and is refused on an older Bun before anything is sent. `pinnedWebSocketOptions` and `createRealtimeWebSocket` hand settings to the `ws` library, which Bun replaces with its own WebSocket, so they are available on Node only.

Deno pins the TLS connection from Deno 2.8.0, the first release whose Node compatibility layer runs the certificate check for both requests and WebSockets; on an older Deno the default transport is EHBP, and `transport: { kind: "tls" }` and `createWebSocket` are refused with a `ConfigurationError`.

**WebSockets from the `openai` package aren't pinned.** The `openai` package's WebSocket classes (`ResponsesWS`, `LiveWS` and its sideband and forks, `OpenAIRealtimeWS`, `OpenAIRealtimeWebSocket` and `OpenAIRealtimeTranslationWS`) take an OpenAI client and open their own WebSocket. Given a Tinfoil client, they connect to its base URL with its API key or bearer token, but without the TLS pin, so the connection isn't bound to the verified enclave. With an enclave or router client:

- For a realtime session, use `createRealtimeWebSocket` instead of `OpenAIRealtimeWS`. It always connects to the verified enclave, even when the client sends its requests through an EHBP proxy.
- For a WebSocket that you drive yourself, `createWebSocket` opens a raw pinned WebSocket to a path on the verified enclave.
- `ResponsesWS`, `LiveWS` and its sideband and forks, and `OpenAIRealtimeTranslationWS` have no Tinfoil replacement. On Node, pass them the pinned settings, for example `new ResponsesWS(client, await pinnedWebSocketOptions(client.httpClient))`. That pins the connection only when the HTTP client has no EHBP proxy, because the class connects to the client's base URL: then it connects to the enclave itself over `wss://`. Behind a proxy, the pinned handshake fails, because the proxy doesn't hold the enclave's key, and over an `http://` proxy there is no TLS to pin at all.

`OpenAIRealtimeWebSocket` uses the runtime's built-in WebSocket and can't be pinned. The gateway client offers no pinned WebSocket, so don't give it to any of these classes.

The request body is still encrypted to the verified enclave's key; the proxy only forwards it, to the enclave named in the `X-Tinfoil-Enclave-Url` header. A `proxyURL`'s path is where the proxy is mounted, not the API path: an `OpenAIClient` joins its `apiPath` (`/v1/` by default) under it, so `https://proxy.example.com/relay` and `https://proxy.example.com/relay/` both give `https://proxy.example.com/relay/v1/`. Multi-user services must scope prompt caches to each end user with the router client's `userCacheSecret` or a per-request `user_cache_secret`; an enclave client never adds one. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).

### HTTP clients and lazy imports

If you supply your own API client and need only the verified HTTP transport, import from `tinfoil`. Its root entry exports the `RouterHTTPClient`, `EnclaveHTTPClient` and `GatewayHTTPClient` classes, their options, Tinfoil errors, catalog and session-recovery helpers, and the pinned WebSockets, and imports neither the OpenAI client nor the AI SDK. The package's browser mappings select the browser transport.

```typescript
import { RouterHTTPClient, type RouterOptions } from "tinfoil";

const options: RouterOptions = { transport: { kind: "ehbp" } };
const client = await RouterHTTPClient.create(options);
// Pass client.fetch to your API client, and close it when finished.
```

To defer downloading and evaluating the transport until a user needs it, dynamically import the same entry inside that action:

```typescript
const { RouterHTTPClient } = await import("tinfoil");
const client = await RouterHTTPClient.create({ transport: { kind: "ehbp" } });
```

A bundler can put this dynamic import in a separate chunk, provided the transport isn't also imported eagerly elsewhere in the application. `tinfoil/openai` is the OpenAI client's entry, and `tinfoil/ai-sdk` the AI SDK's.

### Custom network transport

The EHBP transport of `RouterHTTPClient.create` and `EnclaveHTTPClient.create` takes a `fetch`: a fetch-compatible network implementation that carries their sealed requests, for a native HTTP bridge (such as Tauri's) or a trusted relay. `GatewayHTTPClient.create`, which always uses EHBP, takes it as its `fetch` option, and the AI SDK provider's `createTinfoil` takes it in its `transport`. `createClient` takes only the OpenAI options, so it doesn't take it; build an `OpenAIClient` over an HTTP client instead.

```typescript
import { RouterHTTPClient } from "tinfoil";

// nativeFetch: a fetch-compatible function that sends the sealed requests.
const client = await RouterHTTPClient.create({ transport: { kind: "ehbp", fetch: nativeFetch } });
```

The client verifies the enclave and seals each request body before calling it, and opens the response that it returns; attestation documents and the router list are still fetched with the runtime's fetch, unless `fetchAttestation` or `fetchRouterList` is set, and the gateway catalog is always fetched with it. The function must return a standard `Response` and honour the request's signal, and a relay must pass the sealed body and the protocol headers through unchanged. The method, URL and headers aren't sealed, so a relay sees the API key: use only a relay that you trust, over HTTPS. A request without a body passes through it unsealed, as EHBP leaves it. The TLS transport has no `fetch`, since it pins the connection itself.

## Errors

The clients throw three error classes, each a `TinfoilError` with a `category`, and with the underlying failure as `cause` when there is one: `ConfigurationError` (invalid options, or a closed client), `NetworkError` (the enclave or its attestation couldn't be reached) and `AttestationError` (the enclave couldn't be trusted: when verification rejected the document, `cause` is the verifier's `VerificationError` whose `layer` names the rejecting check and whose `report` shows the step that failed and what the steps before it established; a key that doesn't match the attested one, or one the enclave no longer holds after rotation, is an `AttestationError` too). Switch on `category` (`"configuration"`, `"network"` or `"attestation"`), which is the stable discriminant; each error's `name` matches its class, for logs and stack traces. The factories, `ensureVerified()`, `reverify()` and an HTTP client's `fetch` throw them directly. A call through the OpenAI API surface, such as `client.chat.completions.create(...)`, goes through the OpenAI client's request loop, which catches whatever the attested `fetch` throws, retries the request `maxRetries` times (2 by default, with backoff; only a request whose body is a stream isn't retried) and then throws `APIConnectionError` with the client's error as its `cause`. So an enclave that fails to verify again on a request surfaces as an `APIConnectionError` whose `cause` is an `AttestationError`, after three verification attempts; pass `maxRetries: 0` to the client or the request to see the first failure. `findTinfoilError(err)` from `tinfoil` follows `cause` and returns the SDK error behind an OpenAI error, or undefined when there is none, as for an error from the API itself:

```typescript
import { findTinfoilError } from "tinfoil";

try {
  await client.chat.completions.create({ model: "gpt-oss-120b", messages });
} catch (err) {
  const sdkError = findTinfoilError(err);
  if (sdkError?.category === "attestation") {
    // The enclave couldn't be trusted: don't send it more data.
  }
  throw err;
}
```
 Errors from the API itself (`AuthenticationError`, `RateLimitError` and the rest) keep the OpenAI client's types; all of them are re-exported from `tinfoil/openai`.

## Verification reports

A router or enclave client's `ensureVerified()` returns the report of a verification that admits requests now, verifying first if needed, and `reverify()` verifies again and returns the new report: a `VerificationReport` from `@tinfoilsh/verifier`, whose `steps` show each layer's outcome (`passed`, or `skipped` for a layer that had nothing to check) and whose `verifiedFacts` hold what the enclave proved, such as `codeDigest`, `enclaveMeasurement` and `tlsPublicKeyFP`. `lastVerification()` returns the most recent attempt without network I/O: `{ report }` if it passed, or `{ error }` with the error that the client reported if it failed, so that a later failure replaces an earlier success. When the verifier rejected the document, that error is an `AttestationError` whose `cause` is the verifier's `VerificationError`, and its `report` shows the step that failed and the partial facts, such as the expected and measured registers side by side; a failed fetch is a `NetworkError` with no report. The `onVerification(host, report, error)` option is called once for every attempt, including the retry, a re-verification after an expiry or a key rotation, each router that discovery tries, and each gateway replica:

```typescript
import { RouterHTTPClient } from "tinfoil";
import { VerificationError } from "@tinfoilsh/verifier";

const client = await RouterHTTPClient.create({
  onVerification: (host, report, error) => {
    if (report !== undefined) console.log(host, report.steps);
    else if (error?.cause instanceof VerificationError) console.log(host, error.cause.report.failedStep());
    else console.log(host, error);
  },
});
const last = client.lastVerification();
```

A gateway client's `lastVerification()` returns one entry for each replica that it has tried to verify, with that replica's last attempt. A gateway client's `policy` applies to the pins that set none; a pin's own `policy` replaces it entirely. A `verificationCheck` receives only the verified facts of a verification that passed.

## Documentation

- [JavaScript SDK documentation](https://docs.tinfoil.sh/sdk/javascript-sdk), which describes the 1.x API until 2.0 is released; for 2.0, use this README and the migration guide below.
- Realtime transcription over WebSockets uses `createRealtimeWebSocket(client, { model })` from `tinfoil/openai`, which opens a session over a WebSocket pinned to the attested key.
- [Examples](packages/tinfoil/examples/), including the Vercel AI SDK provider (`createTinfoil` from `tinfoil/ai-sdk`) on the server and in React.
- [Migrating from 1.x to 2.0](https://github.com/tinfoilsh/tinfoil-js/blob/main/MIGRATION.md).
- The resources a client exposes, such as `chat`, `responses`, `embeddings`, and `audio`, keep the OpenAI methods and types; see the [OpenAI Node client documentation](https://github.com/openai/openai-node).
- `tinfoil/unsafe` exports `UnverifiedClient`, which skips attestation: for development against a local server only, never for real data.

## Development

This is a monorepo: `packages/tinfoil` is the SDK (published as `tinfoil`) and `packages/verifier` is the attestation verifier (published as `@tinfoilsh/verifier`).

```bash
npm install
npm run build
npm test                    # unit tests
npm run test:all            # unit, integration, and browser tests
```

Run `npm run build` before testing: the published-entry and bundle tests inspect the emitted package artifacts and fail if they are missing. Rebuild after changing source files or package exports.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
