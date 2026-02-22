# Tinfoil SDK Examples

Working examples demonstrating different ways to use the Tinfoil SDK.

## Server vs Browser

| Environment | Pattern | API Key Handling |
|-------------|---------|------------------|
| **Server** (Node.js, API routes) | `TinfoilAI` or `createTinfoilAI` | Use `apiKey` directly |
| **Browser** (React, Vue, etc.) | `SecureClient` + proxy | Proxy adds key, use `bearerToken` |

**Browser apps require a proxy server** to keep your API key secret. The request body remains encrypted end-to-end—your proxy cannot read it. See [Encrypted Request Proxying](https://docs.tinfoil.sh/guides/proxy-server).

## Prerequisites

Before running any examples:

1. **Get an API key** at [docs.tinfoil.sh/get-api-key](https://docs.tinfoil.sh/get-api-key)
2. **Set your API key:**
   ```bash
   export TINFOIL_API_KEY="your-api-key"
   ```
3. **Install and build** from the monorepo root:
   ```bash
   npm install
   npm run build
   ```

## Examples

### [`chat/`](chat/) — Basic Chat Completion

The simplest way to use Tinfoil. Creates a `TinfoilAI` client and makes a chat completion request.

```bash
cd chat && npx ts-node main.ts
```

**What it demonstrates:**
- Creating a TinfoilAI client (verification happens automatically)
- Making a chat completion request
- Handling the response

**When to use:** Most applications should start here. The `TinfoilAI` client is OpenAI-compatible and handles all verification and encryption automatically.

---

### [`streaming/`](streaming/) — Server-Sent Events Streaming

Stream responses token-by-token as they're generated.

```bash
cd streaming && npx ts-node main.ts
```

**What it demonstrates:**
- Streaming chat completions with `stream: true`
- Processing chunks as they arrive
- Handling the stream end

**When to use:** Chat interfaces, real-time UIs, or any application where you want to display responses progressively.

---

### [`ai-sdk/`](ai-sdk/) — Vercel AI SDK (Server-Side)

Use Tinfoil with the [Vercel AI SDK](https://sdk.vercel.ai/) for server-side AI applications.

```bash
cd ai-sdk && npx ts-node main.ts
```

**What it demonstrates:**
- Creating a Tinfoil provider with `createTinfoilAI`
- Using `generateText` and `streamText` from the AI SDK
- Compatible with all Vercel AI SDK features

**When to use:** Server-side code like Next.js API routes, Node.js backends, or any server environment where you can safely use your API key.

**Related docs:**
- [Tool Calling](https://docs.tinfoil.sh/guides/tool-calling)
- [Structured Outputs](https://docs.tinfoil.sh/guides/structured-outputs)

---

### [`ai-sdk-react/`](ai-sdk-react/) — Vercel AI SDK (Browser/React)

Use Tinfoil with Vercel AI SDK's React hooks (`useChat`) for browser-based chat interfaces.

**Note:** This is a pattern example, not a runnable script. Copy the patterns into your React/Next.js project.

**What it demonstrates:**
- Using `SecureClient` with `DefaultChatTransport`
- Async initialization with loading state
- React `useChat` hook integration
- Context provider pattern for app-wide transport

**When to use:** Browser-based chat interfaces, React apps, Next.js client components. **Requires a proxy server** to keep your API key secret.

**Key files:**
- `lib/tinfoil.ts` — Singleton transport initialization
- `components/Chat.tsx` — React component with `useChat`

**Important:** Always `await secureClient.ready()` before using the fetch function. See the example for proper initialization patterns.

**Related docs:**
- [Encrypted Request Proxying](https://docs.tinfoil.sh/guides/proxy-server) — Proxy server setup
- [Vercel AI SDK Transport](https://ai-sdk.dev/docs/ai-sdk-ui/transport) — Transport customization

---

### [`secure_client/`](secure_client/) — Direct SecureClient Usage

Lower-level access to the secure fetch function for custom HTTP requests.

```bash
cd secure_client && npx ts-node main.ts
```

**What it demonstrates:**
- Creating a `SecureClient` directly
- Using `client.fetch()` for custom HTTP requests
- Accessing raw response data

**When to use:** When you need custom HTTP handling, want to use a different OpenAI client, or need direct control over requests. Also useful for non-chat endpoints.

**Related docs:**
- [Encrypted Request Proxying](https://docs.tinfoil.sh/guides/proxy-server) — Route requests through your backend

---

### [`unverified_client/`](unverified_client/) — Development Without Attestation

Skip attestation verification for local development and testing.

```bash
cd unverified_client && npx ts-node main.ts
```

**What it demonstrates:**
- Importing `UnverifiedClient` from `tinfoil/unsafe`
- Making requests without attestation checks
- Same API as `SecureClient`

**When to use:** Local development, testing, CI/CD pipelines, or when connecting to non-enclave endpoints. **Never use in production** — this bypasses all security verification.

> **Warning:** The `UnverifiedClient` is exported from `tinfoil/unsafe` (not the main `tinfoil` entry point) to prevent accidental production use. It does not verify enclave attestation. Only use for development and testing.

---

## Additional Resources

### Guides

- [Encrypted Request Proxying](https://docs.tinfoil.sh/guides/proxy-server) — Set up a proxy server
- [Tool Calling](https://docs.tinfoil.sh/guides/tool-calling) — Function calling with AI models
- [Structured Outputs](https://docs.tinfoil.sh/guides/structured-outputs) — JSON schema validation
- [Image Processing](https://docs.tinfoil.sh/guides/image-processing) — Multi-modal AI
- [Document Processing](https://docs.tinfoil.sh/guides/document-processing) — PDF/document handling

### Understanding the Security

- [How It Works](https://docs.tinfoil.sh/cc/how-it-works) — Confidential computing overview
- [Attestation Architecture](https://docs.tinfoil.sh/verification/attestation-architecture) — Verification deep-dive

### Full SDK Documentation

- [JavaScript SDK](https://docs.tinfoil.sh/sdk/javascript-sdk)
- [Model Catalog](https://docs.tinfoil.sh/models/catalog)
