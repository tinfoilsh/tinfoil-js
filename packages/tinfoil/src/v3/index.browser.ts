/**
 * The client for browsers: the same surface as the Node entry, with the
 * `"ehbp"` transport the only one available and the default. The user cache
 * secret is kept in memory for the page's life, since nothing persists it.
 * OpenAI clients need an API credential the page may hold: pass it as
 * `bearerToken`, which also allows browser use, or set `dangerouslyAllowBrowser`.
 */
export * from "./surface.js";
