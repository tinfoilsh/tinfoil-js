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

Every attested client is an async factory: one that exists has been verified, and it verifies again by itself when the verification expires or the enclave's key changes. `createClient` takes the OpenAI client's own options and nothing else, so it is a drop-in for `new OpenAI(...)`. Anything about the route itself lives on the configurable clients: `RouterOpenAIClient.create(routerOptions, openaiOptions)` for the discovered router with a proxy, transport mode, verifier or cache-secret setting; `EnclaveOpenAIClient.create(host, repo, options, openaiOptions)` for one enclave instead of the router; and `RouterHTTPClient.create()` / `EnclaveHTTPClient.create(host, repo)` for a verified `fetch` to any HTTP API.

Never put `apiKey` in browser code. Route browser requests through a [proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds the key, and authenticate the browser with a token of your own:

```typescript
import { RouterOpenAIClient } from "tinfoil";

const client = await RouterOpenAIClient.create({ baseURL: "https://proxy.example.com/" }, { bearerToken: "<SESSION_TOKEN>" });
```

The request body is still encrypted to the verified enclave's key; the proxy only forwards it. Multi-user services must scope prompt caches to each end user with `userCacheSecret` or a per-request `user_cache_secret`; see [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).

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
