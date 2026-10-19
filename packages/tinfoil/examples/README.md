# Tinfoil SDK Examples

Set `TINFOIL_API_KEY` ([get one](https://docs.tinfoil.sh/get-api-key)) and run
`npm install && npm run build` from the monorepo root. Then run an example with
`cd <example> && npx ts-node main.ts`, or all of them with `./run-all.sh`.

| Example | Shows |
| --- | --- |
| [`chat/`](chat/) | A basic chat completion with `TinfoilAI` |
| [`streaming/`](streaming/) | Streaming chat completions |
| [`ai-sdk/`](ai-sdk/) | The Vercel AI SDK on the server with `createTinfoilAI` |
| [`ai-sdk-react/`](ai-sdk-react/) | The Vercel AI SDK's `useChat` in a browser app (pattern files, not runnable) |
| [`secure_client/`](secure_client/) | Custom HTTP requests with `SecureClient.fetch` |
| [`unverified_client/`](unverified_client/) | `UnverifiedClient` from `tinfoil/unsafe`, which skips attestation; for development only, never in production |

Browser apps must not hold the API key: route requests through a
[proxy server](https://docs.tinfoil.sh/guides/proxy-server) that adds it, and
authenticate with `bearerToken`. Request bodies stay encrypted to the enclave,
so the proxy cannot read them.

See the [JavaScript SDK documentation](https://docs.tinfoil.sh/sdk/javascript-sdk) for more.
