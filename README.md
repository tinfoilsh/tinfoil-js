# Tinfoil TypeScript SDK

[![Build Status](https://github.com/tinfoilsh/tinfoil-js/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-js/actions)
[![NPM version](https://img.shields.io/npm/v/tinfoil.svg)](https://npmjs.org/package/tinfoil)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/javascript-sdk)

Secure OpenAI-compatible client for the Tinfoil API. This SDK verifies enclave attestation and encrypts all payloads using [HPKE (RFC 9180)](https://www.rfc-editor.org/rfc/rfc9180.html) via the [EHBP protocol](https://github.com/tinfoilsh/encrypted-http-body-protocol). It also supports a fallback mode to TLS certificate pinning, where all connections are encrypted and terminated to a verified secure enclave. 

## Installation

```bash
npm install tinfoil
```

Requires Node 20+. Works in browsers with ES2022 support. Bun is supported via TLS pinning fallback (see [Bun Support](#bun-support)).

## Quick Start

```typescript
import { TinfoilAI } from "tinfoil";

const client = new TinfoilAI({
  apiKey: "<YOUR_API_KEY>", // or use TINFOIL_API_KEY env var
});

const completion = await client.chat.completions.create({
  messages: [{ role: "user", content: "Hello!" }],
  model: "llama3-3-70b",
});
```

## Browser Usage

Use `bearerToken` for browser authentication (e.g., JWT from your auth system):

```javascript
import { TinfoilAI } from 'tinfoil';

const client = new TinfoilAI({
  bearerToken: 'your-jwt-token'
});

await client.ready();

const completion = await client.chat.completions.create({
  model: 'llama3-3-70b',
  messages: [{ role: 'user', content: 'Hello!' }]
});
```

> **Warning:** Using API keys in the browser exposes them to anyone viewing your page source. If you must use `apiKey` instead of `bearerToken` in the browser, set `dangerouslyAllowBrowser: true`.

## Using with OpenAI SDK

If you prefer using the OpenAI SDK directly, use `SecureClient` to get a verified secure fetch:

```typescript
import OpenAI from "openai";
import { SecureClient } from "tinfoil";

const secureClient = new SecureClient();
await secureClient.ready();

const openai = new OpenAI({
  apiKey: "<YOUR_API_KEY>",
  baseURL: secureClient.getBaseURL(),
  fetch: secureClient.fetch,
});

const completion = await openai.chat.completions.create({
  model: "llama3-3-70b",
  messages: [{ role: "user", content: "Hello!" }],
});
```

## Verification API

```typescript
import { Verifier } from "tinfoil";

const verifier = new Verifier({ serverURL: "https://enclave.host.com" });

const attestation = await verifier.verify();
console.log(attestation.tlsPublicKeyFingerprint);
console.log(attestation.hpkePublicKey);

const doc = verifier.getVerificationDocument();
console.log(doc.securityVerified);
console.log(doc.steps); // fetchDigest, verifyCode, verifyEnclave, compareMeasurements
```

## How Verification Works

Verification happens **automatically** when you create a `TinfoilAI` or `SecureClient`:

1. **Enclave Attestation**: Fetches AMD SEV-SNP attestation from the enclave
2. **Code Verification**: Verifies the running code matches the signed release via Sigstore
3. **Measurement Comparison**: Compares hardware measurements against expected values
4. **Secure Transport**: Establishes HPKE-encrypted connection (or TLS-pinned for Bun)

The `Verifier` class is for advanced use cases where you want to verify an enclave **before** creating a client, or verify arbitrary enclaves independently.

### Transport Modes

- **HPKE (default)**: End-to-end encrypted via RFC 9180, works through proxies
- **TLS Pinning**: Fallback for Bun (no X25519 WebCrypto support yet)

## Project Structure

This is a monorepo with two packages:

| Package | Description |
|---------|-------------|
| `packages/tinfoil` | Main SDK (published as `tinfoil`) |
| `packages/verifier` | Attestation verifier (published as `@tinfoilsh/verifier`) |

Browser builds use a separate entry point (`index.browser.ts`) selected via conditional exports. Runtime environment detection handles differences between Node.js, Bun, and browsers.

## Development

```bash
# Install dependencies
npm install

# Build all packages (verifier first, then tinfoil)
npm run build

# Run all unit tests
npm test

# Run all tests (unit + integration + browser)
npm run test:all

# Run browser unit tests
npm run test:browser

# Run integration tests (makes real network requests)
npm run test:integration
npm run test:browser:integration

# Run Bun tests
npm run test:bun -w tinfoil
npm run test:bun:integration -w tinfoil

# Clean build artifacts
npm run clean
```

## Documentation

- [TinfoilAI SDK Documentation](https://docs.tinfoil.sh/sdk/javascript-sdk)
- [OpenAI Client Reference](https://github.com/openai/openai-node) (API is compatible)
- [Examples](https://github.com/tinfoilsh/tinfoil-js/blob/main/packages/tinfoil/examples/README.md)

## Bun Support

Bun is supported with automatic fallback to TLS certificate pinning. Since Bun doesn't yet support X25519 in WebCrypto's `crypto.subtle` API, the EHBP encrypted transport is not available. Instead, the SDK automatically falls back to TLS pinning, which still provides verified secure connections to the enclave.

> **Note:** EHBP provides additional features relative to TLS pinning, including [encrypted request proxying](https://docs.tinfoil.sh/guides/proxy-server) which keeps requests encrypted even through infrastructure proxies. These features will become available in Bun once X25519 WebCrypto support is added.

```typescript
import { TinfoilAI } from "tinfoil";

const client = new TinfoilAI({
  apiKey: "<YOUR_API_KEY>",
});

// Works the same as Node.js - TLS fallback is automatic
const completion = await client.chat.completions.create({
  messages: [{ role: "user", content: "Hello!" }],
  model: "llama3-3-70b",
});
```

To run the Bun-specific tests:

```bash
npm run test:bun -w tinfoil
```

## Reporting Vulnerabilities

Email [security@tinfoil.sh](mailto:security@tinfoil.sh) or open a GitHub issue. 
