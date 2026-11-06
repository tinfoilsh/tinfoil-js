# Vercel AI SDK React Integration

Pattern files for using Tinfoil with the Vercel AI SDK's `useChat` hook in a
browser app. They are not a runnable app; copy them into your Next.js project.

- `lib/tinfoil.ts` creates one `RouterHTTPClient` routed through your proxy
  (the factory verifies the enclave before it returns) and wraps it as a
  `useChat` transport. `useChat` speaks the AI SDK's own protocol, not the
  OpenAI chat completions API that the enclave serves, so the transport
  translates: it runs `streamText` over an OpenAI-compatible provider bound to
  the client's `fetch` and streams the result back as UI message chunks. The
  transport is reused across the app.
- `components/Chat.tsx` renders a chat with `useChat`, mounted once the
  transport exists.

```bash
npm install tinfoil ai @ai-sdk/react @ai-sdk/openai-compatible
```

The browser must not hold your API key. Set up a
[proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds it, and
set `NEXT_PUBLIC_PROXY_URL` to its URL. The request body stays encrypted to the
enclave, so the proxy cannot read it. See
the AI SDK [transport docs](https://ai-sdk.dev/docs/ai-sdk-ui/transport) for
customization.
