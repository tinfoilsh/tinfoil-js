/**
 * Bun integration tests - verify both EHBP and TLS transports work with real Tinfoil API
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

  it("should create TinfoilAI client with EHBP transport (default)", async () => {
    if (!isBun || !RUN_INTEGRATION) return;

    const { TinfoilAI } = await import("../src/index.js");
    const client = new TinfoilAI({
      apiKey: process.env.TINFOIL_API_KEY,
      // transport defaults to 'ehbp'
    });
    await client.ready();

    const doc = client.inspect()?.verification;
    expect(doc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
  });

  it("should make chat completion via EHBP transport (default)", async () => {
    if (!isBun || !RUN_INTEGRATION) return;

    const { TinfoilAI } = await import("../src/index.js");
    const client = new TinfoilAI({
      apiKey: process.env.TINFOIL_API_KEY,
    });

    const completion = await client.chat.completions.create({
      model: "gpt-oss-120b",
      messages: [{ role: "user", content: "Hello!" }],
    });

    expect(completion.choices[0].message.content).toBeDefined();
  });

  it("should create TinfoilAI client with TLS transport", async () => {
    if (!isBun || !RUN_INTEGRATION) return;

    const { TinfoilAI } = await import("../src/index.js");
    const client = new TinfoilAI({
      apiKey: process.env.TINFOIL_API_KEY,
      transport: 'tls',
    });
    await client.ready();

    const doc = client.inspect()?.verification;
    expect(doc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
  });

  it("should make chat completion via TLS transport", async () => {
    if (!isBun || !RUN_INTEGRATION) return;

    const { TinfoilAI } = await import("../src/index.js");
    const client = new TinfoilAI({
      apiKey: process.env.TINFOIL_API_KEY,
      transport: 'tls',
    });

    const completion = await client.chat.completions.create({
      model: "gpt-oss-120b",
      messages: [{ role: "user", content: "Hello!" }],
    });

    expect(completion.choices[0].message.content).toBeDefined();
  });

  it("should create Client with TLS transport", async () => {
    if (!isBun || !RUN_INTEGRATION) return;

    const { Client } = await import("../src/index.js");
    const client = new Client({ transport: 'tls' });
    await client.ready();

    const doc = client.inspect()?.verification;
    expect(doc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
    expect(client.getBaseURL()).toBeDefined();
  });
});
