// Browser entry point - uses same consolidated modules as server
// Runtime detection in secure-fetch.ts handles browser-specific behavior
export { TinfoilAI } from "./tinfoil-ai.js";
export { TinfoilAI as default } from "./tinfoil-ai.js";

export * from "./verifier.js";
export * from "./ai-sdk-provider.js";
export * from "./config.js";
export { SecureClient, type TransportMode } from "./secure-client.js";
export { UnverifiedClient } from "./unverified-client.js";