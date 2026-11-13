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
| `tinfoil` (the OpenAI clients), `tinfoil/http` and `tinfoil/unsafe` | `npm install tinfoil@next` |
| `tinfoil/ai-sdk` (the Vercel AI SDK provider) | `npm install tinfoil@next ai @ai-sdk/openai-compatible` |

`ai` and `@ai-sdk/openai-compatible` are optional peer dependencies, so installing `tinfoil` doesn't install them. `tinfoil/ai-sdk` imports `@ai-sdk/openai-compatible`; `ai` is what your own code calls with the provider. Importing `tinfoil/ai-sdk` without `@ai-sdk/openai-compatible` fails with a module-not-found error that names the package.

## Quick Start

```typescript
import { createClient } from "tinfoil";

// Discovers Tinfoil's inference router and verifies it before returning.
const client = await createClient({ apiKey: "<YOUR_API_KEY>" });

const completion = await client.chat.completions.create({
  messages: [{ role: "user", content: "Hello!" }],
  model: "gpt-oss-120b", // see https://docs.tinfoil.sh/models/chat
});
```

Every attested client is an async factory: one that exists has been verified, and it verifies again by itself when the verification expires or the enclave's key changes. `createClient` takes the OpenAI client's own options (except `baseURL` and `fetch`, which the attested transport owns) plus `bearerToken`, and returns a client with the same API as `new OpenAI(...)`. Anything about the route itself lives on the configurable clients: `RouterOpenAIClient.create(routerOptions, openaiOptions)` for the discovered router with a proxy, transport mode, verifier or cache-secret setting; `EnclaveOpenAIClient.create(host, repo, options, openaiOptions)` for one enclave instead of the router; and `RouterHTTPClient.create()` / `EnclaveHTTPClient.create(host, repo)` for a verified `fetch` to any HTTP API. An HTTP client's `close()` releases its pooled connections and refuses further use, and both kinds of client support `await using` (an OpenAI client closes the HTTP client under it).

Never put `apiKey` in browser code: the OpenAI clients and the AI SDK provider refuse it outside Node and Bun, `dangerouslyAllowBrowser` or not. Route browser requests through a [proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds the key, and authenticate the browser with a token of your own:

```typescript
import { RouterOpenAIClient } from "tinfoil";

const client = await RouterOpenAIClient.create({ baseURL: "https://proxy.example.com/v1/" }, { bearerToken: "<SESSION_TOKEN>" });
```

Browsers use the EHBP transport, the default and the only one available there. The package's type declarations are shared with the Node build, so a browser project type-checks a few names that throw a `ConfigurationError` when called: `createWebSocket` and `pinnedWebSocketOptions` (a verified WebSocket pins the server certificate, which browsers don't expose to scripts), `createRealtimeWebSocket` (a realtime session runs over such a WebSocket), and `transportMode: "tls"` (the `"tls"` transport mode pins the server certificate too; `"ehbp"` seals request and response bodies to the enclave's key instead).

Bun pins the TLS connection from Bun 1.4.0, the first release whose `fetch` checks the server certificate before it sends the request; on an older Bun the default transport mode is `"ehbp"` and `transportMode: "tls"` is refused with a `ConfigurationError`. `createWebSocket` needs Bun 1.4.4 or later, the first release whose WebSocket runs the certificate check at all, and is refused on an older Bun before anything is sent. `pinnedWebSocketOptions` and `createRealtimeWebSocket` hand settings to the `ws` library, which Bun replaces with its own WebSocket, so they are available on Node only.

**WebSockets from the `openai` package aren't pinned.** The `openai` package's WebSocket classes (`ResponsesWS`, `LiveWS` and its sideband and forks, `OpenAIRealtimeWS`, `OpenAIRealtimeWebSocket` and `OpenAIRealtimeTranslationWS`) take an OpenAI client and open their own WebSocket. Given a Tinfoil client, they connect to its base URL with its API key or bearer token, but without the TLS pin, so the connection isn't bound to the verified enclave. With an enclave or router client, use `createRealtimeWebSocket` or `createWebSocket` instead: they always connect to the verified enclave, even when the client sends its requests through a proxy `baseURL`. To use one of the `ws`-based classes anyway, the client must connect to the enclave directly, without a proxy `baseURL`, because the class connects to the client's base URL. Then pass it the pinned settings, for example `new ResponsesWS(client, await pinnedWebSocketOptions(client.httpClient))` on Node. Behind a proxy, the pinned handshake fails, because the proxy doesn't hold the enclave's key. `OpenAIRealtimeWebSocket` uses the runtime's built-in WebSocket and can't be pinned. The gateway client offers no pinned WebSocket, so don't give it to any of these classes.

The request body is still encrypted to the verified enclave's key; the proxy only forwards it. `baseURL` is the API root, as for `new OpenAI({ baseURL })`: the client appends `chat/completions` and the other OpenAI paths to it, so a proxy that forwards paths as they are takes the enclave's `/v1/`. Multi-user services must scope prompt caches to each end user with `userCacheSecret` or a per-request `user_cache_secret`; see [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).

### HTTP-only and lazy imports

If you supply your own API client and need only the verified HTTP transport, import from `tinfoil/http`. It exports the same `RouterHTTPClient`, `EnclaveHTTPClient` and `GatewayHTTPClient` classes, their options, Tinfoil errors, catalog and session-recovery helpers, without importing the OpenAI client or AI SDK adapters. The package's browser mappings still select the browser transport; verification and encryption are unchanged.

```typescript
import { RouterHTTPClient, type RouterOptions } from "tinfoil/http";

const options: RouterOptions = { transportMode: "ehbp" };
const client = await RouterHTTPClient.create(options);
// Pass client.fetch to your API client, and close it when finished.
```

To defer downloading and evaluating the transport until a user needs it, dynamically import the same entry inside that action:

```typescript
const { RouterHTTPClient } = await import("tinfoil/http");
const client = await RouterHTTPClient.create({ transportMode: "ehbp" });
```

A bundler can put this dynamic import in a separate chunk, provided the transport isn't also imported eagerly elsewhere in the application. The root `tinfoil` imports remain available for the OpenAI-compatible clients and helpers, and `tinfoil/ai-sdk` remains the AI SDK entry.

### Custom network transport

`RouterHTTPClient.create`, `EnclaveHTTPClient.create` and `GatewayHTTPClient.create`, and the route options of the OpenAI clients over them (`RouterOpenAIClient.create(routerOptions, openaiOptions)` and the enclave and gateway equivalents), take a `fetch` option: a fetch-compatible network implementation that carries their requests in the EHBP transport mode, for a native HTTP bridge (such as Tauri's) or a trusted relay. The AI SDK provider's `createTinfoil` takes it too. `createClient` takes only the OpenAI options, so it doesn't take it.

```typescript
import { RouterHTTPClient } from "tinfoil/http";

// nativeFetch: a fetch-compatible function that sends the sealed requests.
const client = await RouterHTTPClient.create({ fetch: nativeFetch, transportMode: "ehbp" }); // "ehbp" is already the default in browsers
```

The client verifies the enclave and seals each request body before calling it, and opens the response that it returns; attestation documents, the router list and the gateway catalog are still fetched with the runtime's fetch. The function must return a standard `Response` and honour the request's signal, and a relay must pass the sealed body and the protocol headers through unchanged. The method, URL and headers aren't sealed, so a relay sees the API key: use only a relay that you trust, over HTTPS. A request without a body passes through it unsealed, as the mode leaves it. The option is refused with `transportMode: "tls"`, which pins the connection itself.

## Errors

The clients throw three error classes, each a `TinfoilError` with a `category`, and with the underlying failure as `cause` when there is one: `ConfigurationError` (invalid options, or a closed client), `NetworkError` (the enclave or its attestation couldn't be reached) and `AttestationError` (the enclave couldn't be trusted: when verification rejected the document, `cause` is the verifier's `VerificationError` whose `layer` names the rejecting check; a key that doesn't match the attested one, or one the enclave no longer holds after rotation, is an `AttestationError` too). Switch on `category` (`"configuration"`, `"network"` or `"attestation"`), which is the stable discriminant; each error's `name` matches its class, for logs and stack traces. The factories, `ensureVerified()`, `reverify()` and an HTTP client's `fetch` throw them directly. A call through the OpenAI API surface, such as `client.chat.completions.create(...)`, goes through the OpenAI client's request loop, which catches whatever the attested `fetch` throws, retries the request `maxRetries` times (2 by default, with backoff; only a request whose body is a stream isn't retried) and then throws `APIConnectionError` with the client's error as its `cause`. So an enclave that fails to verify again on a request surfaces as an `APIConnectionError` whose `cause` is an `AttestationError`, after three verification attempts; pass `maxRetries: 0` to the client or the request to see the first failure. Errors from the API itself (`AuthenticationError`, `RateLimitError` and the rest) keep the OpenAI client's types; all of them are re-exported from the package root.

## Documentation

- [JavaScript SDK documentation](https://docs.tinfoil.sh/sdk/javascript-sdk). Realtime transcription over WebSockets is covered in [Processing audio](https://docs.tinfoil.sh/guides/processing-audio): `createRealtimeWebSocket(client, { model })` opens a session over a WebSocket pinned to the attested key.
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
