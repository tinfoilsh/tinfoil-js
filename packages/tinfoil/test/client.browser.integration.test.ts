import { describe, it, expect } from 'vitest';
import { TinfoilAI } from '../src/tinfoil-ai';
import { Client } from '../src/client';
import { UnverifiedClient } from '../src/unverified-client';

describe('Browser Client Integration Tests', () => {
  describe('TinfoilAI Client', () => {
    it('should create a TinfoilAI client and make a chat completion request', async () => {
      const client = new TinfoilAI({
        bearerToken: process.env.TINFOIL_API_KEY,
      });

      expect(client).toBeDefined();

      await client.ready();

      const completion = await client.chat.completions.create({
        messages: [{ role: 'user', content: 'Hello!' }],
        model: 'gpt-oss-120b',
        max_tokens: 5,
      });

      expect(completion).toBeDefined();
      expect(Array.isArray(completion.choices)).toBe(true);
      expect(completion.choices.length).toBeGreaterThan(0);

      const firstChoice = completion.choices[0];
      expect(firstChoice).toBeDefined();
      expect(firstChoice.message).toBeDefined();
    }, 60000);

    it('should get verification document after client initialization', async () => {
      const client = new TinfoilAI({
        bearerToken: process.env.TINFOIL_API_KEY,
      });

      await client.ready();

      const verificationDoc = client.inspect()?.verification;

      expect(verificationDoc).toBeDefined();
      expect(verificationDoc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
      expect(verificationDoc?.hpkePublicKey()).toBeTruthy();
    }, 60000);

    it('should handle streaming chat completion', async () => {
      const client = new TinfoilAI({
        bearerToken: process.env.TINFOIL_API_KEY,
      });

      await client.ready();

      const stream = await client.chat.completions.create({
        messages: [
          { role: 'system', content: 'No matter what the user says, only respond with: Done.' },
          { role: 'user', content: 'Is this a test?' },
        ],
        model: 'gpt-oss-120b',
        max_tokens: 5,
        stream: true,
      });

      let chunksReceived = 0;

      for await (const chunk of stream) {
        chunksReceived++;
      }

      expect(chunksReceived).toBeGreaterThan(0);
    }, 60000);
  });

  describe('Client', () => {
    it('should create a Client and make a direct fetch request', async () => {
      const client = new Client();

      expect(client).toBeDefined();

      await client.ready();

      const response = await client.fetch('/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.TINFOIL_API_KEY}`,
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Hello!' }],
        }),
      });

      expect(response).toBeDefined();
      expect(response.status).toBe(200);
      expect(response.headers).toBeDefined();

      const responseBody = await response.json();
      expect(responseBody).toBeDefined();
      expect(Array.isArray(responseBody.choices)).toBe(true);
      expect(responseBody.choices.length).toBeGreaterThan(0);

      const firstChoice = responseBody.choices[0];
      expect(firstChoice).toBeDefined();
      expect(firstChoice.message).toBeDefined();
    }, 60000);

    it('should get verification document from Client', async () => {
      const client = new Client();
      await client.ready();

      const verificationDoc = client.inspect()?.verification;

      expect(verificationDoc).toBeDefined();
      expect(verificationDoc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
    }, 60000);
  });

  describe('UnverifiedClient', () => {
    it('should create an UnverifiedClient and make a direct fetch request', async () => {
      const client = new UnverifiedClient();

      expect(client).toBeDefined();

      await client.ready();

      const response = await client.fetch('/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.TINFOIL_API_KEY}`,
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Hello!' }],
        }),
      });

      expect(response).toBeDefined();
      expect(response.status).toBe(200);

      const responseBody = await response.json();
      expect(responseBody).toBeDefined();
      expect(Array.isArray(responseBody.choices)).toBe(true);
      expect(responseBody.choices.length).toBeGreaterThan(0);
    }, 60000);

    it('should return undefined when inspecting an UnverifiedClient', async () => {
      const client = new UnverifiedClient();
      await client.ready();

      expect(client.inspect()).toBeUndefined();
    }, 30000);
  });

  describe('Client initialization options', () => {
    it('should initialize UnverifiedClient correctly when enclaveURL is provided but baseURL is not', async () => {
      const client = new UnverifiedClient({
        enclaveURL: 'https://inference.tinfoil.sh'
      });

      await client.ready();

      expect(client).toBeDefined();
      expect(client.fetch).toBeDefined();
    }, 30000);

    it('should initialize UnverifiedClient correctly when baseURL is provided but enclaveURL is not', async () => {
      const client = new UnverifiedClient({
        baseURL: 'https://inference.tinfoil.sh/v1/'
      });

      await client.ready();

      expect(client).toBeDefined();
      expect(client.fetch).toBeDefined();
    }, 30000);

    it('Client should initialize correctly when enclaveURL is provided but baseURL is not', async () => {
      const client = new Client({
        enclaveURL: 'https://inference.tinfoil.sh'
      });

      await client.ready();

      expect(client).toBeDefined();
      expect(client.fetch).toBeDefined();

      const doc = client.inspect()?.verification;
      expect(doc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
    }, 60000);

    it('Client should initialize correctly when baseURL is provided but enclaveURL is not', async () => {
      const client = new Client({
        baseURL: 'https://inference.tinfoil.sh/v1/'
      });

      await client.ready();

      expect(client).toBeDefined();
      expect(client.fetch).toBeDefined();

      const doc = client.inspect()?.verification;
      expect(doc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
    }, 60000);
  });
});
