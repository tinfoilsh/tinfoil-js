import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";

describe("Examples Integration Tests", () => {
  describe("Basic Chat Example", () => {
    it.skipIf(!RUN_INTEGRATION)("should create a TinfoilAI client and make a chat completion request", async () => {
      const { TinfoilAI } = await import("../src/tinfoil-ai");

      const client = new TinfoilAI({
        apiKey: process.env.TINFOIL_API_KEY,
      });

      expect(client).toBeTruthy();

      await client.ready();

      const completion = await client.chat.completions.create({
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
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient();
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
      const { TinfoilAI } = await import("../src/tinfoil-ai");
      const client = new TinfoilAI({ apiKey: process.env.TINFOIL_API_KEY });

      await client.ready();

      const stream = await client.chat.completions.create({
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

  describe("Audio Transcription", () => {
    it.skipIf(!RUN_INTEGRATION)("should transcribe audio using whisper-large-v3-turbo model", async () => {
      const { TinfoilAI } = await import("../src/tinfoil-ai");
      const client = new TinfoilAI({ apiKey: process.env.TINFOIL_API_KEY });

      await client.ready();

      const audioPath = path.join(__dirname, "fixtures", "test.mp3");
      const audioFile = fs.createReadStream(audioPath);

      const transcription = await client.audio.transcriptions.create({
        model: "whisper-large-v3-turbo",
        file: audioFile,
      });

      expect(transcription).toBeTruthy();
      expect(typeof transcription.text).toBe("string");
      expect(transcription.text.trim().startsWith("I want to start off by saying")).toBe(true);
    });
  });

  describe("Transport Mode Options", () => {
    it.skipIf(!RUN_INTEGRATION)("should work with transport: 'auto' (default)", async () => {
      const { SecureClient } = await import("../src/secure-client");

      const client = new SecureClient({ transport: 'auto' });
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
