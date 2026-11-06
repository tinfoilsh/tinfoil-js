/**
 * The client for browsers: the same surface as the Node entry, with the
 * `"ehbp"` transport the only one available and the default. The user cache
 * secret is kept in memory for the page's life, since nothing persists it.
 * An OpenAI client in a page takes its credential as `bearerToken`: a
 * short-lived token from the application's own sign-in, which also allows
 * browser use. A long-lived API key belongs on a server, and is refused here.
 *
 * The type declarations are shared with the Node build, so a browser
 * project type-checks a few names that this build refuses with a
 * `ConfigurationError` when they are called: the pinned WebSockets
 * (`createWebSocket` and `pinnedWebSocketOptions`), realtime sessions
 * (`createRealtimeWebSocket`), and the `"tls"` transport mode, since a
 * browser exposes nothing of the TLS connection that they would pin.
 */
export * from "./surface.js";
