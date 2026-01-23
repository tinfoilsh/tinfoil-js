# Vercel AI SDK React Integration

This example demonstrates how to use Tinfoil with the Vercel AI SDK's React hooks (`useChat`) for building secure chat interfaces.

## Architecture

```
Browser (React App)
    │
    │  Encrypted request (HPKE)
    │  X-Tinfoil-Enclave-Url header
    ▼
Your Proxy Server
    │
    │  Adds TINFOIL_API_KEY
    │  Cannot decrypt body
    ▼
Tinfoil Enclave
    │
    │  Decrypts & processes
    ▼
Response (encrypted)
```

## Key Concepts

### 1. Browser Requires Proxy

In browser environments, you **must** use a proxy server to:
- Keep your `TINFOIL_API_KEY` secret (never expose to browser)
- Forward encrypted requests to the Tinfoil enclave

The request body remains encrypted end-to-end—your proxy cannot read it.

### 2. Async Initialization

The `SecureClient` must complete attestation verification before use:

```typescript
// ❌ WRONG - fetch won't work yet
const client = new SecureClient({ baseURL: proxyUrl });
const transport = new DefaultChatTransport({ fetch: client.fetch });

// ✅ CORRECT - wait for ready()
const client = new SecureClient({ baseURL: proxyUrl });
await client.ready(); // Performs attestation
const transport = new DefaultChatTransport({ fetch: client.fetch });
```

### 3. Singleton Pattern

Initialize the transport once and reuse it across your app to avoid repeated attestation.

## Files

- `lib/tinfoil.ts` — Singleton initialization pattern
- `components/Chat.tsx` — React component with `useChat`

## Setup

This is a pattern example, not a runnable app. To use in your Next.js project:

1. **Install dependencies:**
   ```bash
   npm install tinfoil ai @ai-sdk/react
   ```

2. **Set up your proxy server:**
   See [Encrypted Request Proxying](https://docs.tinfoil.sh/guides/proxy-server)

3. **Copy the pattern files** into your project and adapt as needed.

4. **Set environment variable:**
   ```bash
   NEXT_PUBLIC_PROXY_URL=https://your-proxy.com
   ```

## Related Documentation

- [Encrypted Request Proxying](https://docs.tinfoil.sh/guides/proxy-server) — Full proxy setup guide
- [Vercel AI SDK Transport](https://ai-sdk.dev/docs/ai-sdk-ui/transport) — Transport customization
- [Vercel AI SDK useChat](https://ai-sdk.dev/docs/reference/ai-sdk-ui/use-chat) — Hook reference
