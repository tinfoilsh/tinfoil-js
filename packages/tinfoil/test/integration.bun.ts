/**
 * Bun integration tests - verify TLS fallback works with real Tinfoil API
 * Run with: bun test test/integration.bun.ts
 * 
 * These tests require:
 * - RUN_TINFOIL_INTEGRATION=true environment variable
 * - TINFOIL_API_KEY environment variable with valid API key
 */
import { describe, it, expect, beforeAll } from "bun:test";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const isBun = typeof process !== "undefined" && (process as any).versions?.bun;

describe("Bun Integration", () => {
  beforeAll(() => {
    if (!isBun) console.log("Skipping - not running in Bun");
    if (!RUN_INTEGRATION) console.log("Skipping - RUN_TINFOIL_INTEGRATION not set");
  });

  it("should create TinfoilAI client with TLS fallback", async () => {
    if (!isBun || !RUN_INTEGRATION) return;
    
    const { TinfoilAI } = await import("../src/index.js");
    const client = new TinfoilAI({ apiKey: process.env.TINFOIL_API_KEY });
    await client.ready();
    
    const doc = await client.getVerificationDocument();
    expect(doc.securityVerified).toBe(true);
  });

  it("should make chat completion via TLS fallback", async () => {
    if (!isBun || !RUN_INTEGRATION) return;
    
    const { TinfoilAI } = await import("../src/index.js");
    const client = new TinfoilAI({ apiKey: process.env.TINFOIL_API_KEY });
    
    const completion = await client.chat.completions.create({
      model: "llama3-3-70b",
      messages: [{ role: "user", content: "Say 'test'" }],
      max_tokens: 10,
    });
    
    expect(completion.choices[0].message.content).toBeDefined();
  });

  it("should create SecureClient with TLS fallback", async () => {
    if (!isBun || !RUN_INTEGRATION) return;
    
    const { SecureClient } = await import("../src/index.js");
    const client = new SecureClient();
    await client.ready();
    
    const doc = await client.getVerificationDocument();
    expect(doc.securityVerified).toBe(true);
    expect(client.getBaseURL()).toBeDefined();
  });
});
