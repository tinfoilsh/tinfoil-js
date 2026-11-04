/**
 * The `tinfoil/v3/ai-sdk` entry: a provider for the Vercel AI SDK over an
 * attested client. It is its own entry so the AI SDK stays out of bundles
 * that don't use it. The provider has no platform-specific code of its own;
 * the clients it builds on resolve to their browser variants through the
 * package's browser field, as from the main entry.
 */
export { createTinfoil, type TinfoilProvider, type TinfoilProviderOptions, type TinfoilProviderEnclave } from "./internal/ai-sdk.js";
