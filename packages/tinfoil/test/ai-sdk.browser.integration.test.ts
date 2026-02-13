import { describe, it, expect } from 'vitest';
import { SecureClient } from '../src/secure-client';

/**
 * AI SDK Browser Integration Tests
 * 
 * These tests verify that SecureClient.fetch works correctly when used
 * in patterns similar to the Vercel AI SDK's DefaultChatTransport.
 * 
 * The tests simulate how the AI SDK would consume the fetch function:
 * - Passing fetch to transport-like consumers
 * - Streaming responses
 * - Custom headers
 */
describe('AI SDK Browser Transport Tests', () => {
  describe('SecureClient.fetch as transport', () => {
    it('should work when passed to a transport-like consumer', async () => {
      const client = new SecureClient();
      await client.ready();

      // Simulate how DefaultChatTransport uses fetch
      const transportFetch = client.fetch;

      const response = await transportFetch('/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b-free',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Say hello' }],
        }),
      });

      expect(response).toBeDefined();
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data.choices).toBeDefined();
      expect(data.choices.length).toBeGreaterThan(0);
    }, 60000);

    it('should handle streaming responses like AI SDK transport', async () => {
      const client = new SecureClient();
      await client.ready();

      // Simulate streaming request like DefaultChatTransport
      const response = await client.fetch('/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream',
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b-free',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Count 1 2 3' }],
          stream: true,
        }),
      });

      expect(response).toBeDefined();
      expect(response.status).toBe(200);
      expect(response.body).toBeDefined();

      // Read the stream like AI SDK would
      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      let receivedChunks = 0;
      let fullContent = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        receivedChunks++;
        const chunk = decoder.decode(value, { stream: true });
        fullContent += chunk;
      }

      expect(receivedChunks).toBeGreaterThan(0);
      expect(fullContent.length).toBeGreaterThan(0);
      // SSE format includes "data:" prefix
      expect(fullContent).toContain('data:');
    }, 60000);

    it('should preserve custom headers for proxy routing', async () => {
      const client = new SecureClient();
      await client.ready();

      // Custom headers that a transport might add for proxy
      // These are visible to the proxy but NOT to the enclave body
      const response = await client.fetch('/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Custom-Header': 'test-value', // Would be used by proxy
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b-free',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Hello' }],
        }),
      });

      expect(response).toBeDefined();
      expect(response.status).toBe(200);
    }, 60000);

    it('should handle AbortController for request cancellation', async () => {
      const client = new SecureClient();
      await client.ready();

      const controller = new AbortController();

      // Start a streaming request
      const fetchPromise = client.fetch('/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream',
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b-free',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Write a very long story' }],
          stream: true,
        }),
        signal: controller.signal,
      });

      // Abort after a short delay
      setTimeout(() => controller.abort(), 100);

      try {
        const response = await fetchPromise;
        // If we get here, try to read and abort during stream
        const reader = response.body!.getReader();
        try {
          while (true) {
            const { done } = await reader.read();
            if (done) break;
            controller.abort();
          }
        } catch (e: any) {
          // AbortError is expected
          expect(e.name === 'AbortError' || e.message.includes('abort')).toBe(true);
        }
      } catch (e: any) {
        // AbortError during fetch is also acceptable
        expect(e.name === 'AbortError' || e.message.includes('abort')).toBe(true);
      }
    }, 60000);

    it('should work with URL object input', async () => {
      const client = new SecureClient();
      await client.ready();

      const baseURL = client.getBaseURL()!;
      const url = new URL('/v1/chat/completions', baseURL);

      const response = await client.fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b-free',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Hello' }],
        }),
      });

      expect(response).toBeDefined();
      expect(response.status).toBe(200);
    }, 60000);
  });

  describe('Initialization timing', () => {
    it('should throw or handle gracefully if fetch used before ready()', async () => {
      const client = new SecureClient();
      
      // Don't await ready() - this simulates the common mistake
      // The fetch should either queue the request or throw a clear error
      
      // Note: The actual behavior depends on implementation.
      // The SecureClient.fetch getter already handles this by awaiting ready()
      // internally, so this should still work but will be slower.
      const response = await client.fetch('/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'gpt-oss-120b-free',
          max_tokens: 5,
          messages: [{ role: 'user', content: 'Hello' }],
        }),
      });

      // Should still work because fetch internally awaits ready()
      expect(response.status).toBe(200);
    }, 60000);

    it('should verify attestation completes before making requests', async () => {
      const client = new SecureClient();
      
      // ready() should complete verification
      await client.ready();
      
      const doc = await client.getVerificationDocument();
      expect(doc.securityVerified).toBe(true);
      expect(doc.steps.verifyEnclave.status).toBe('success');
      expect(doc.steps.verifyCode.status).toBe('success');
      expect(doc.steps.compareMeasurements.status).toBe('success');
    }, 60000);
  });
});
