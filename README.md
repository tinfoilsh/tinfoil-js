# Tinfoil TypeScript Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-js/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-js/actions)
[![NPM version](https://img.shields.io/npm/v/tinfoil.svg)](https://npmjs.org/package/tinfoil)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/javascript-sdk)

A TypeScript client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Node client](https://github.com/openai/openai-node) with the same API, and before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it. Works in Node 20+, browsers, Electron, and Bun, and supports the [Vercel AI SDK](https://sdk.vercel.ai/).

For complete documentation, see the [JavaScript SDK documentation](https://docs.tinfoil.sh/sdk/javascript-sdk).

## Installation

```bash
npm install tinfoil
```

## Quick Start

```typescript
import { TinfoilAI } from "tinfoil";

const client = new TinfoilAI({
  apiKey: "<YOUR_API_KEY>", // or set TINFOIL_API_KEY
});

// Enclave verification and encryption happen automatically.
const completion = await client.chat.completions.create({
  messages: [{ role: "user", content: "Hello!" }],
  model: "llama3-3-70b", // see https://docs.tinfoil.sh/models/catalog
});
```

### Browser usage

Never put `apiKey` in browser code. Route requests through a [proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds the key, and authenticate the browser with `bearerToken`. Request bodies stay encrypted to the enclave, so the proxy cannot read them.

```typescript
const client = new TinfoilAI({
  bearerToken: "your-jwt-token",
  baseURL: "https://your-proxy.com/",
});
await client.ready();
```

### Realtime (WebSockets)

`client.realtime()` opens a WebSocket session pinned to the attested enclave key and returns an `OpenAIRealtimeWS` client from the OpenAI SDK. Node.js only: browsers cannot pin TLS connections. Realtime always connects directly to the enclave, even when a proxy `baseURL` is configured.

```typescript
const rt = await client.realtime({ model: "voxtral-mini-4b-realtime" });
rt.on("session.created", (event) => console.log(event));
rt.send({ type: "input_audio_buffer.append", audio: base64AudioChunk });
```

### Vercel AI SDK

```typescript
import { createTinfoilAI } from "tinfoil";
import { generateText } from "ai";

const tinfoil = await createTinfoilAI("<YOUR_API_KEY>");
const { text } = await generateText({ model: tinfoil("llama3-3-70b"), prompt: "Hello!" });
```

For browser apps, pass `secureClient.fetch` to `DefaultChatTransport`; see the [React example](packages/tinfoil/examples/ai-sdk-react/).

## Verification document

```typescript
import { SecureClient } from "tinfoil";

const secureClient = new SecureClient();
await secureClient.ready();

const doc = secureClient.getVerificationDocument();
console.log(doc.securityVerified);
console.log(doc.steps); // fetchDigest, verifyCode, verifyEnclave, compareMeasurements, verifyCertificate
```

`SecureClient` also exposes a verified `fetch` and `getBaseURL()` for use with the OpenAI SDK or any HTTP library. The lower-level `Verifier` class verifies an enclave without creating a client.

## Prompt Cache Scoping

The router partitions prompt caches by API identity and a `user_cache_secret` that the SDK adds to eligible requests. By default, Node.js generates one and persists it at `~/.tinfoil/user_cache_secret`, and browsers use a runtime-lifetime value; either is suitable for single-user applications. Multi-user services should scope each request to its end user:

```typescript
// Pin a stable, opaque secret for this client (or set TINFOIL_USER_CACHE_SECRET in Node.js).
// SecureClient and createTinfoilAI accept the same option.
const client = new TinfoilAI({ userCacheSecret: secret });

// A per-request value wins over the client-level secret.
const completion = await client.chat.completions.create({
  model: "llama3-3-70b",
  messages: [{ role: "user", content: "Hello!" }],
  user_cache_secret: perUserSecret,
} as TinfoilAI.Chat.ChatCompletionCreateParams);
```

See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching) for resolution order and guidance on choosing a scope.

## Examples

Working examples are in [`packages/tinfoil/examples/`](packages/tinfoil/examples/): basic chat, streaming, Vercel AI SDK (server and React), direct `SecureClient` usage, and an unverified client for development.

## API Documentation

This library is a drop-in replacement for the [official OpenAI Node client](https://github.com/openai/openai-node). All methods and types are identical; see the [OpenAI Node client documentation](https://github.com/openai/openai-node) for API usage.

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
