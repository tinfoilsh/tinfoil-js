# Tinfoil TypeScript SDK

[![Build Status](https://github.com/tinfoilsh/tinfoil-js/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-js/actions)
[![NPM version](https://img.shields.io/npm/v/tinfoil.svg)](https://npmjs.org/package/tinfoil)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/javascript-sdk)

A TypeScript client for verifiably private AI inference with the [Tinfoil API](https://docs.tinfoil.sh/introduction). Supports the [OpenAI API format](https://platform.openai.com/docs/api-reference) and the [Vercel AI SDK](https://sdk.vercel.ai/).

Tinfoil runs LLMs inside [secure enclaves](https://docs.tinfoil.sh/cc/how-it-works)—isolated environments on hardware where even Tinfoil cannot access your data. This SDK encrypts your requests using [HPKE (RFC 9180)](https://www.rfc-editor.org/rfc/rfc9180.html) via the [EHBP](https://github.com/tinfoilsh/encrypted-http-body-protocol) protocol, so that only the verified enclave can decrypt them.


It also supports TLS certificate pinning as an alternative transport mode, where all connections are encrypted and terminated to a verified secure enclave.


## Installation

```bash
npm install tinfoil
```

Requires Node 20+. Works in browsers with ES2020 support, Electron, and Bun (see [Bun Support](#bun-support)).



## Quick Start

You'll need an [API key](https://docs.tinfoil.sh/get-api-key) to get started.

```typescript
import { TinfoilAI } from "tinfoil";

const client = new TinfoilAI({
  apiKey: "<YOUR_API_KEY>", // or use TINFOIL_API_KEY env var
});

const completion = await client.chat.completions.create({
  messages: [{ role: "user", content: "Hello!" }],
  model: "llama3-3-70b", // See all models: https://docs.tinfoil.sh/models/catalog
});
```



## Browser Usage

Use `bearerToken` for browser authentication (e.g., JWT from your auth system):

```typescript
import { TinfoilAI } from 'tinfoil';

const client = new TinfoilAI({
  bearerToken: 'your-jwt-token' // From your auth system
});

await client.ready(); // Wait for verification to complete

const completion = await client.chat.completions.create({
  model: 'llama3-3-70b',
  messages: [{ role: 'user', content: 'Hello!' }]
});
```

> **Warning:** Never use `apiKey` in browser code—it exposes your key in page source. Use `bearerToken` with your backend authentication. If you must use `apiKey` instead of `bearerToken` in the browser, set `dangerouslyAllowBrowser: true`.



## Using with OpenAI SDK

If you prefer the OpenAI SDK directly, use `SecureClient` to get a verified fetch function:

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



## Using with Vercel AI SDK

Full support for the [Vercel AI SDK](https://sdk.vercel.ai/) in both server and browser environments.

### AI Server SDK (Node.js / Next.js)

Use `createTinfoilAI` for server-side AI SDK functions:

```typescript
import { createTinfoilAI } from "tinfoil";
import { generateText, streamText } from "ai";

const tinfoil = await createTinfoilAI("<YOUR_API_KEY>");

const { text } = await generateText({
  model: tinfoil("llama3-3-70b"),
  prompt: "Hello!",
});
```

For Next.js API routes, initialize once at module level to avoid repeated verification:

```typescript
// app/api/chat/route.ts
const tinfoilPromise = createTinfoilAI(process.env.TINFOIL_API_KEY!);

export async function POST(req: Request) {
  const tinfoil = await tinfoilPromise;
  // ...
}
```

See the [Vercel AI Server SDK Example](packages/tinfoil/examples/ai-sdk/) for more details.

### AI Browser SDK (React / Vue / etc.)

For browser apps, use `SecureClient` with `DefaultChatTransport`. A [proxy server](https://docs.tinfoil.sh/guides/proxy-server) is required to keep your API key secret.

```typescript
import { SecureClient } from "tinfoil";
import { DefaultChatTransport } from "ai";

const secureClient = new SecureClient({
  baseURL: "https://your-proxy.com/",
});
await secureClient.ready(); // Wait for attestation

const transport = new DefaultChatTransport({
  api: "/v1/chat/completions",
  fetch: secureClient.fetch,
});
```

See the [Vercel AI Browser SDK Example](packages/tinfoil/examples/ai-sdk-react/) for complete React patterns with `useChat`, context providers, and error handling.



## How Verification Works

When you create a client, the SDK **automatically**:

1. **Verifies the enclave** — Fetches attestation and checks AMD SEV-SNP hardware signatures to prove it's a genuine secure enclave
2. **Verifies the code** — Confirms the running code matches the signed GitHub release (via Sigstore)
3. **Establishes encryption** — Creates an encrypted connection that only the verified enclave can decrypt

Your requests are encrypted before leaving your machine. Even Tinfoil cannot read them—only the verified enclave can decrypt and process your data.

#### Transport Modes:

- **HPKE (default)**: End-to-end encrypted via RFC 9180, works through proxies
- **TLS Pinning**: Direct TLS certificate pinning to the enclave (requires direct connection, no proxy support)

For a deeper understanding, see [How It Works](https://docs.tinfoil.sh/cc/how-it-works), [Confidentiality](https://docs.tinfoil.sh/cc/confidentiality), [Verifiability](https://docs.tinfoil.sh/cc/verifiability) and [Attestation Architecture](https://docs.tinfoil.sh/verification/attestation-architecture).

### Verification API

The `Verifier` class is for advanced use cases where you want to verify an enclave **before** creating a client, or verify arbitrary enclaves independently.

```typescript
import { Verifier } from "tinfoil";

const verifier = new Verifier({
  serverURL: "https://enclave.host.com",
  configRepo: "tinfoilsh/confidential-model-router",
});

const attestation = await verifier.verify();
console.log(attestation.tlsPublicKeyFingerprint);
console.log(attestation.hpkePublicKey);

const doc = verifier.getVerificationDocument();
console.log(doc.securityVerified);
console.log(doc.steps); // fetchDigest, verifyCode, verifyEnclave, compareMeasurements
```

## Proxy Support

Route requests through your own backend while keeping request bodies encrypted end-to-end. This lets you:
- Keep API keys on your server
- Add authentication, rate limiting, logging
- The proxy sees headers/URLs but **cannot decrypt request or response bodies**

```typescript
import { SecureClient } from "tinfoil";

const client = new SecureClient({
  baseURL: "https://your-proxy-server.com/",
});

await client.ready();
// Requests go to your proxy, bodies remain encrypted to the enclave
```

For full proxy server implementation (Go example, CORS config, header handling), see the [Encrypted Request Proxying guide](https://docs.tinfoil.sh/guides/proxy-server).



## Examples

Working examples are in [`packages/tinfoil/examples/`](packages/tinfoil/examples/):

| Example | Description |
|---------|-------------|
| [`chat/`](packages/tinfoil/examples/chat/) | Basic chat completion with TinfoilAI |
| [`streaming/`](packages/tinfoil/examples/streaming/) | Server-sent events streaming |
| [`ai-sdk/`](packages/tinfoil/examples/ai-sdk/) | Vercel AI SDK server-side integration |
| [`ai-sdk-react/`](packages/tinfoil/examples/ai-sdk-react/) | Vercel AI SDK React/browser integration |
| [`secure_client/`](packages/tinfoil/examples/secure_client/) | Direct SecureClient usage for custom HTTP |
| [`unverified_client/`](packages/tinfoil/examples/unverified_client/) | Development/testing without attestation (`tinfoil/unsafe`) |

Run any example:

```bash
cd packages/tinfoil/examples/chat
npx ts-node main.ts
```



## Documentation

### Guides

- [Encrypted Request Proxying](https://docs.tinfoil.sh/guides/proxy-server) — Set up a proxy server
- [Tool Calling](https://docs.tinfoil.sh/guides/tool-calling) — Function calling with AI models
- [Structured Outputs](https://docs.tinfoil.sh/guides/structured-outputs) — JSON schema validation
- [Image Processing](https://docs.tinfoil.sh/guides/image-processing) — Multi-modal AI
- [Document Processing](https://docs.tinfoil.sh/guides/document-processing) — PDF/document handling

### Understanding the Security

- [How It Works](https://docs.tinfoil.sh/cc/how-it-works) — Confidential computing overview
- [Confidentiality](https://docs.tinfoil.sh/cc/confidentiality) — Data privacy guarantees
- [Verifiability](https://docs.tinfoil.sh/cc/verifiability) — Attestation explanation
- [Attestation Architecture](https://docs.tinfoil.sh/verification/attestation-architecture) — Technical deep-dive
- [EHBP Protocol](https://docs.tinfoil.sh/resources/ehbp) — Encryption protocol specification

### Tutorials

- [Cline with Tinfoil](https://docs.tinfoil.sh/tutorials/cline) — Private AI-assisted coding in VS Code
- [Private RAG with Verba](https://docs.tinfoil.sh/tutorials/verba) — Build private RAG applications

### Resources

- [Model Catalog](https://docs.tinfoil.sh/models/catalog) — Available models
- [Getting an API Key](https://docs.tinfoil.sh/get-api-key) — Sign up
- [SDK Overview](https://docs.tinfoil.sh/sdk/overview) — All Tinfoil SDKs
- [Status](https://docs.tinfoil.sh/resources/status) — Service status
- [Changelog](https://docs.tinfoil.sh/resources/changelog) — What's new



## Project Structure

This is a monorepo with two packages:

| Package | Description |
|---------|-------------|
| `packages/tinfoil` | Main SDK (published as `tinfoil`) |
| `packages/verifier` | Attestation verifier (published as `@tinfoilsh/verifier`) |



## Development

```bash
# Install dependencies
npm install

# Build all packages
npm run build

# Run tests
npm test                    # Unit tests
npm run test:all            # All tests (unit + integration + browser)
npm run test:integration    # Integration tests (real network requests)
npm run test:browser        # Browser tests
npm run test:bun -w tinfoil # Bun tests
```



## Reporting Vulnerabilities

Email [security@tinfoil.sh](mailto:security@tinfoil.sh) or open a GitHub issue.
