/**
 * Realtime sessions against the live enclave: a pinned WebSocket to the
 * realtime endpoint opens, and a realtime session started through the
 * OpenAI client receives a server event. Needs the integration lane and a
 * Tinfoil API key.
 */
import { describe, expect, it } from "vitest";
import { EnclaveHTTPClient } from "../src/enclave-client.js";
import { EnclaveOpenAIClient } from "../src/openai-client.js";
import type { PinnedWebSocket } from "../src/options.js";
import { createRealtimeWebSocket } from "../src/realtime.js";
import { createWebSocket } from "../src/websocket.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const HOST = "inference.tinfoil.sh";
const ROUTER = "tinfoilsh/confidential-model-router";
const PIN = { repo: ROUTER, project: ROUTER };
const MODEL = "voxtral-mini-4b-realtime";
const apiKey = process.env.TINFOIL_API_KEY ?? "";

function opened(socket: PinnedWebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for open")), 30_000);
    socket.addEventListener("open", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
    socket.addEventListener("error", (event) => {
      clearTimeout(timer);
      reject(event.error ?? new Error(event.message));
    }, { once: true });
  });
}

describe("realtime against the live enclave", () => {
  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "opens a pinned WebSocket to the realtime endpoint",
    async () => {
      const client = await EnclaveHTTPClient.create(HOST, PIN);
      const socket = await createWebSocket(client, `/v1/realtime?model=${MODEL}`, { headers: { Authorization: `Bearer ${apiKey}` } });
      await opened(socket);
      socket.close();
    },
    60_000,
  );

  it.skipIf(!RUN_INTEGRATION || apiKey === "")(
    "starts a realtime session through the OpenAI client and receives a server event",
    async () => {
      const ai = await EnclaveOpenAIClient.create(HOST, PIN, {}, { apiKey });
      const rt = await createRealtimeWebSocket(ai, { model: MODEL });
      const first = await new Promise<{ type?: string }>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("timed out waiting for a server event")), 30_000);
        rt.on("event", (event) => {
          clearTimeout(timer);
          resolve(event as { type?: string });
        });
        rt.on("error", (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      expect(first).toHaveProperty("type");
      rt.close();
    },
    60_000,
  );
});
