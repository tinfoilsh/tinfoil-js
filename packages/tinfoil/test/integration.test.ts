import { describe, it, expect, beforeAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";

/**
 * Integration tests for the Tinfoil SDK.
 *
 * Clients are shared across tests where they use the same configuration to
 * avoid redundant attestation round-trips — attestation is tested elsewhere.
 */
describe("Examples Integration Tests", () => {
  // Shared TinfoilAI client (default config) for chat, streaming, and audio tests
  let sharedTinfoilClient: any;
  // Shared default SecureClient for direct fetch and default transport tests
  let sharedSecureClient: any;

  beforeAll(async () => {
    if (!RUN_INTEGRATION) return;
    const { TinfoilAI } = await import("../src/tinfoil-ai");
    const { SecureClient } = await import("../src/secure-client");

    sharedTinfoilClient = new TinfoilAI({ apiKey: process.env.TINFOIL_API_KEY });
    sharedSecureClient = new SecureClient();

    // Attest both in parallel
    await Promise.all([
      sharedTinfoilClient.ready(),
      sharedSecureClient.ready(),
    ]);
  });

  describe("Basic Chat Example", () => {
    it.skipIf(!RUN_INTEGRATION)("should create a TinfoilAI client and make a chat completion request", async () => {
      const completion = await sharedTinfoilClient.chat.completions.create({
        messages: [{ role: "user", content: "Hello!" }],
        model: "gpt-oss-120b-free",
        max_tokens: 5,
      });

      expect(completion).toBeTruthy();
      expect(Array.isArray(completion.choices)).toBe(true);
      expect(completion.choices.length).toBeGreaterThan(0);

      const firstChoice = completion.choices[0];
      expect(firstChoice).toBeTruthy();
      expect(firstChoice.message).toBeTruthy();
    });
  });

  describe("Secure Client Example", () => {
    it.skipIf(!RUN_INTEGRATION)("should create a SecureClient and make a direct fetch request", async () => {
      const response = await sharedSecureClient.fetch("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-oss-120b-free",
          max_tokens: 5,
          messages: [{ role: "user", content: "Hello!" }],
        }),
      });

      expect(response).toBeTruthy();
      expect(response.status).toBe(200);

      const responseBody = await response.json();
      expect(responseBody).toBeTruthy();
      expect(Array.isArray(responseBody.choices)).toBe(true);
      expect(responseBody.choices.length).toBeGreaterThan(0);
    });
  });

  describe("EHBP Unverified Client Example", () => {
    it.skipIf(!RUN_INTEGRATION)("should create a UnverifiedClient with EHBP configuration", async () => {
      const { UnverifiedClient } = await import("../src/unverified-client");

      const client = new UnverifiedClient();
      expect(client).toBeTruthy();

      await client.ready();

      const response = await client.fetch("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-oss-120b-free",
          max_tokens: 5,
          messages: [{ role: "user", content: "Hello!" }],
        }),
      });

      expect(response).toBeTruthy();
      expect(response.status).toBe(200);
    });
  });

  describe("Streaming Chat Completion", () => {
    it.skipIf(!RUN_INTEGRATION)("should handle streaming chat completion", async () => {
      const stream = await sharedTinfoilClient.chat.completions.create({
        messages: [
          { role: "system", content: "No matter what the user says, only respond with: Done." },
          { role: "user", content: "Is this a test?" },
        ],
        model: "gpt-oss-120b-free",
        max_tokens: 5,
        stream: true,
      });

      let chunksReceived = 0;

      for await (const chunk of stream) {
        chunksReceived++;
      }

      expect(chunksReceived).toBeGreaterThan(0);
    });

    it("should initialize correctly when keyOrigin is provided but baseURL is not", async () => {
      const { UnverifiedClient } = await import("../src/unverified-client");

      const client = new UnverifiedClient({
        keyOrigin: "https://example-enclave.com",
      });

      await client.ready();

      expect(client).toBeTruthy();
      expect(client.fetch).toBeTruthy();
    });

    it("SecureClient should fail with invalid attestation bundle URL", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        attestationBundleURL: "https://invalid-bundle-url.example.com/bundle",
      });

      await expect(client.ready()).rejects.toThrow();
    });

    it("should initialize correctly when baseURL is provided but keyOrigin is not", async () => {
      const { UnverifiedClient } = await import("../src/unverified-client");

      const client = new UnverifiedClient({
        baseURL: "https://example-api.com/v1/",
      });

      await client.ready();

      expect(client).toBeTruthy();
      expect(client.fetch).toBeTruthy();
    });

  });

  describe("Custom Enclave (non-ATC) Path", () => {
    it.skipIf(!RUN_INTEGRATION)("should verify and fetch using enclaveURL (assembleAttestationBundle)", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        enclaveURL: "https://inference.tinfoil.sh",
      });

      await client.ready();

      const doc = await client.getVerificationDocument();
      expect(doc.securityVerified).toBe(true);
      expect(doc.enclaveHost).toBe("inference.tinfoil.sh");

      const response = await client.fetch("/v1/models", { method: "GET" });
      expect(response.status).toBe(200);
    });

    it.skipIf(!RUN_INTEGRATION)("should verify with enclaveURL and explicit configRepo", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({
        enclaveURL: "https://inference.tinfoil.sh",
        configRepo: "tinfoilsh/confidential-model-router",
      });

      await client.ready();

      const doc = await client.getVerificationDocument();
      expect(doc.securityVerified).toBe(true);
      expect(doc.configRepo).toBe("tinfoilsh/confidential-model-router");
    });
  });

  describe("Audio Transcription", () => {
    it.skipIf(!RUN_INTEGRATION)("should transcribe audio using whisper-large-v3-turbo model", async () => {
      const audioPath = path.join(__dirname, "fixtures", "test.mp3");
      const audioFile = fs.createReadStream(audioPath);

      const transcription = await sharedTinfoilClient.audio.transcriptions.create({
        model: "whisper-large-v3-turbo",
        file: audioFile,
      });

      expect(transcription).toBeTruthy();
      expect(typeof transcription.text).toBe("string");
      expect(transcription.text.trim().startsWith("I want to start off by saying")).toBe(true);
    });
  });

  describe("Transport Mode Options", () => {
    it.skipIf(!RUN_INTEGRATION)("should work with default transport (ehbp)", async () => {
      // Reuses the shared default SecureClient (which uses default ehbp transport)
      const response = await sharedSecureClient.fetch("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-oss-120b-free",
          max_tokens: 5,
          messages: [{ role: "user", content: "Hello!" }],
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.choices.length).toBeGreaterThan(0);
    });

    it.skipIf(!RUN_INTEGRATION)("should work with transport: 'ehbp'", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ transport: 'ehbp' });
      await client.ready();

      const response = await client.fetch("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-oss-120b-free",
          max_tokens: 5,
          messages: [{ role: "user", content: "Hello!" }],
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.choices.length).toBeGreaterThan(0);
    });

    it.skipIf(!RUN_INTEGRATION)("should work with transport: 'tls'", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ transport: 'tls' });
      await client.ready();

      const response = await client.fetch("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-oss-120b-free",
          max_tokens: 5,
          messages: [{ role: "user", content: "Hello!" }],
        }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.choices.length).toBeGreaterThan(0);
    });

    it.skipIf(!RUN_INTEGRATION)("TinfoilAI should work with transport: 'tls'", async () => {
      const { TinfoilAI } = await import("../src/tinfoil-ai");

      const client = new TinfoilAI({
        apiKey: process.env.TINFOIL_API_KEY,
        transport: 'tls',
      });

      await client.ready();

      const completion = await client.chat.completions.create({
        messages: [{ role: "user", content: "Hello!" }],
        model: "gpt-oss-120b-free",
        max_tokens: 5,
      });

      expect(completion.choices.length).toBeGreaterThan(0);
    });
  });
});
