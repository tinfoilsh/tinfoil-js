# Vercel AI SDK React Integration

Pattern files for using Tinfoil with the Vercel AI SDK's `useChat` hook in a
browser app. They are not a runnable app; copy them into your Next.js project.

- `lib/tinfoil.ts` creates one `SecureClient`, awaits `ready()` (attestation)
  before handing its `fetch` to `DefaultChatTransport`, and reuses the transport
  across the app.
- `components/Chat.tsx` renders a chat with `useChat`.

```bash
npm install tinfoil ai @ai-sdk/react
```

The browser must not hold your API key. Set up a
[proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds it, and
set `NEXT_PUBLIC_PROXY_URL` to its URL. The request body stays encrypted to the
enclave, so the proxy cannot read it. See
the AI SDK [transport docs](https://ai-sdk.dev/docs/ai-sdk-ui/transport) for
customization.
