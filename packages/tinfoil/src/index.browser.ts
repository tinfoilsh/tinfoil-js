/**
 * The client for browsers: the same surface as the Node entry, with the
 * `"ehbp"` transport the only one available and the default. The user cache
 * secret is kept in memory for the page's life, since nothing persists it.
 * An OpenAI client in a page takes its credential as `bearerToken`: a
 * short-lived token from the application's own sign-in, which also allows
 * browser use. A long-lived API key belongs on a server, and is refused here.
 */
export * from "./surface.js";
