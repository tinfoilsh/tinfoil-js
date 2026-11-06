# Tinfoil TypeScript Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-js/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-js/actions)
[![NPM version](https://img.shields.io/npm/v/tinfoil.svg)](https://npmjs.org/package/tinfoil)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/javascript-sdk)

A TypeScript client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Node client](https://github.com/openai/openai-node) with the same API. A client verifies the enclave's attestation before it is returned, and every request it sends is bound to the verified enclave: on Node and Bun the TLS connection is pinned to the attested key, and in browsers the request body is encrypted to the attested key with [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it. Works in Node (22.23.4+, 24.22.1+, or 26.12.1+), browsers, Electron, and Bun, and supports the [Vercel AI SDK](https://sdk.vercel.ai/).

## Installation

```bash
npm install tinfoil
```

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

The request body is still encrypted to the verified enclave's key; the proxy only forwards it. `baseURL` is the API root, as for `new OpenAI({ baseURL })`: the client appends `chat/completions` and the other OpenAI paths to it, so a proxy that forwards paths as they are takes the enclave's `/v1/`. Multi-user services must scope prompt caches to each end user with `userCacheSecret` or a per-request `user_cache_secret`; see [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).

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

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
