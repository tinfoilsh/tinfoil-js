import { describe, it, expect } from "vitest";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";

describe("Realtime WebSocket Integration Tests", () => {
  it.skipIf(!RUN_INTEGRATION)(
    "opens a pinned realtime session and receives a server event",
    async () => {
      const { TinfoilAI } = await import("../src/tinfoil-ai");
      const client = new TinfoilAI({ apiKey: process.env.TINFOIL_API_KEY });

      const rt = await client.realtime({ model: "voxtral-mini-4b-realtime" });

      const firstEvent = await new Promise<any>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error("timed out waiting for server event")),
          30_000,
        );
        rt.on("event", (event) => {
          clearTimeout(timeout);
          resolve(event);
        });
        rt.on("error", (err) => {
          clearTimeout(timeout);
          reject(err);
        });
      });

      expect(firstEvent).toHaveProperty("type");
      rt.close();
    },
    60_000,
  );

  it.skipIf(!RUN_INTEGRATION)(
    "SecureClient.createWebSocket connects to the realtime endpoint",
    async () => {
      const { SecureClient } = await import("../src/secure-client");
      const client = new SecureClient();

      const socket = await client.createWebSocket(
        "/v1/realtime?model=voxtral-mini-4b-realtime",
        {
          wsOptions: {
            headers: { Authorization: `Bearer ${process.env.TINFOIL_API_KEY}` },
          },
        },
      );

      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error("timed out waiting for open")),
          30_000,
        );
        socket.on("open", () => {
          clearTimeout(timeout);
          resolve();
        });
        socket.on("error", (err) => {
          clearTimeout(timeout);
          reject(err);
        });
      });

      socket.close();
    },
    60_000,
  );
});
