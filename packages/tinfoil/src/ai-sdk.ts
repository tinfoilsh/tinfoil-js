/**
 * The `tinfoil/ai-sdk` entry: a provider for the Vercel AI SDK over an
 * attested client. It is its own entry so the AI SDK stays out of bundles
 * that don't use it. The provider has no platform-specific code of its own;
 * the clients it builds on resolve to their browser variants through the
 * package's browser field, as from the main entry. That is why this entry
 * and `tinfoil/unsafe` have no `browser` condition in the package's exports
 * map: a bundler substitutes the internal modules that the browser field
 * lists, so neither entry needs a browser build of its own.
 */
export { createTinfoil, type TinfoilProvider, type TinfoilProviderOptions, type TinfoilProviderEnclave } from "./internal/ai-sdk.js";
