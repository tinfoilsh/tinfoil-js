# Tinfoil TypeScript Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-js/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-js/actions)
[![NPM version](https://img.shields.io/npm/v/tinfoil.svg)](https://npmjs.org/package/tinfoil)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/javascript-sdk)

A TypeScript client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Node client](https://github.com/openai/openai-node) with the same API, and before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it. Works in Node 20+, browsers, Electron, and Bun, and supports the [Vercel AI SDK](https://sdk.vercel.ai/).

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
  model: "gpt-oss-120b", // see https://docs.tinfoil.sh/models/chat
});
```

Never put `apiKey` in browser code: route browser requests through a [proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds the key, and authenticate the browser with `bearerToken`. Multi-user services must scope prompt caches to each end user with `userCacheSecret` or a per-request `user_cache_secret`; see [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).

## Documentation

- [JavaScript SDK documentation](https://docs.tinfoil.sh/sdk/javascript-sdk), including `SecureClient` and verification documents. Realtime transcription over WebSockets is covered in [Processing audio](https://docs.tinfoil.sh/guides/processing-audio).
- [Examples](packages/tinfoil/examples/), including the Vercel AI SDK on the server and in React.
- All OpenAI methods and types are unchanged; see the [OpenAI Node client documentation](https://github.com/openai/openai-node).

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
