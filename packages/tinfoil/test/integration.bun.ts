/**
 * Bun integration tests - verify TLS fallback works with real Tinfoil API
 * Run with: bun test test/integration.bun.ts
 * 
 * These tests require:
 * - RUN_TINFOIL_INTEGRATION=true environment variable
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
    const client = new TinfoilAI({ apiKey: "tinfoil" });
    await client.ready();
    
    const doc = await client.getVerificationDocument();
    expect(doc.securityVerified).toBe(true);
  });

  it("should make chat completion via TLS fallback", async () => {
    if (!isBun || !RUN_INTEGRATION) return;
    
    const { TinfoilAI } = await import("../src/index.js");
    const client = new TinfoilAI({ apiKey: "tinfoil" });
    
    const completion = await client.chat.completions.create({
      model: "gpt-oss-120b-free",
      messages: [{ role: "user", content: "Hello!" }],
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
