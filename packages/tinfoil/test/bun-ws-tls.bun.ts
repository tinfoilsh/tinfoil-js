/**
 * Bun WebSocket TLS-pinning capability probe.
 * Run with: bun test test/bun-ws-tls.bun.ts   (needs network access)
 *
 * Background: our pinning model verifies the enclave's leaf TLS public key
 * (SPKI fingerprint from attestation) via a `checkServerIdentity` callback.
 * In Node, the `ws` package forwards that callback to `tls.connect`. Bun
 * replaces `ws` with a native implementation that drops it, so WebSocket
 * pinning fails closed on Bun.
 *
 * This file records, as executable assertions, exactly which Bun primitives
 * honor `checkServerIdentity` as of the tested Bun version — so a future Bun
 * release that closes the gap will flip a test and tell us a cleaner path
 * opened up. Findings on Bun 1.3.14:
 *   - Native `WebSocket` `tls` bag: IGNORES checkServerIdentity (pin skipped).
 *   - `node:tls` `tls.connect`: HONORS it and exposes `cert.raw` — the only
 *     viable primitive for a Bun WebSocket pinning path (hand-rolled framing
 *     over a manually pinned socket).
 */
import { describe, it, expect } from "bun:test";
import * as tls from "tls";
import { X509Certificate, createHash } from "crypto";
import { createCheckServerIdentity } from "../src/pinned-tls-fetch.js";

const isBun = typeof process !== "undefined" && (process as any).versions?.bun;
const WSS_URL = "wss://echo.websocket.org";
const TLS_HOST = "echo.websocket.org";

type WsProbe = { outcome: "open" | "error" | "close"; invoked: boolean };

/** Opens a Bun WebSocket with the given check and reports the terminal outcome. */
function wsProbe(
  check: (host: string, cert: any) => Error | undefined,
): Promise<WsProbe> {
  return new Promise((resolve) => {
    const state: WsProbe = { outcome: "close", invoked: false };
    let settled = false;
    const done = (outcome: WsProbe["outcome"]) => {
      if (settled) return;
      settled = true;
      state.outcome = outcome;
      resolve(state);
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
    const ws = new WebSocket(WSS_URL, {
      // @ts-ignore - Bun-specific TLS options on the WebSocket constructor
      tls: {
        checkServerIdentity: (host: string, cert: any) => {
          state.invoked = true;
          return check(host, cert);
        },
      },
    });
    ws.addEventListener("open", () => done("open"));
    ws.addEventListener("error", () => done("error"));
    ws.addEventListener("close", () => done("close"));
    setTimeout(() => done("close"), 10_000);
  });
}

type TlsProbe = {
  connected: boolean;
  error?: string;
  invoked: boolean;
  certRaw?: Buffer;
};

/** Opens a node:tls socket with the given check and reports the outcome. */
function tlsProbe(
  check: (host: string, cert: any) => Error | undefined,
): Promise<TlsProbe> {
  return new Promise((resolve) => {
    const state: TlsProbe = { connected: false, invoked: false };
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve(state);
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
    };
    const socket = tls.connect(
      {
        host: TLS_HOST,
        port: 443,
        servername: TLS_HOST,
        checkServerIdentity: (host: string, cert: any) => {
          state.invoked = true;
          state.certRaw = cert?.raw;
          return check(host, cert);
        },
      },
      () => {
        state.connected = true;
        done();
      },
    );
    socket.on("error", (e: Error) => {
      state.error = e.message;
      done();
    });
    setTimeout(done, 10_000);
  });
}

function spkiFingerprint(certRaw: Buffer): string {
  const der = new X509Certificate(certRaw).publicKey.export({
    type: "spki",
    format: "der",
  });
  return createHash("sha256")
    .update(der as Buffer)
    .digest("hex");
}

describe("Bun WebSocket TLS pinning capability", () => {
  it("native WebSocket IGNORES tls.checkServerIdentity (pin silently skipped)", async () => {
    if (!isBun) return;

    // A rejecting check must NOT prevent the connection on current Bun: the
    // callback is never invoked. If this ever starts rejecting, Bun has wired
    // checkServerIdentity into its WebSocket and we can pin via it directly.
    const result = await wsProbe(() => new Error("intentional pin failure"));

    expect(result.invoked).toBe(false);
    expect(result.outcome).toBe("open");
  }, 15_000);

  it("node:tls tls.connect HONORS checkServerIdentity and exposes cert.raw", async () => {
    if (!isBun) return;

    const accepted = await tlsProbe(() => undefined);
    expect(accepted.invoked).toBe(true);
    expect(accepted.connected).toBe(true);
    expect(accepted.certRaw).toBeDefined();
    expect(accepted.certRaw!.length).toBeGreaterThan(0);

    const rejected = await tlsProbe(() => new Error("intentional pin failure"));
    expect(rejected.invoked).toBe(true);
    expect(rejected.connected).toBe(false);
    expect(rejected.error).toContain("intentional pin failure");
  }, 25_000);

  it("production createCheckServerIdentity pins correctly over node:tls", async () => {
    if (!isBun) return;

    // Capture the live leaf key, then drive the real production pin function.
    const probed = await tlsProbe(() => undefined);
    expect(probed.certRaw).toBeDefined();
    const correctFp = spkiFingerprint(probed.certRaw!);

    const match = await tlsProbe(createCheckServerIdentity(correctFp));
    expect(match.connected).toBe(true);

    const mismatch = await tlsProbe(
      createCheckServerIdentity(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
    );
    expect(mismatch.connected).toBe(false);
    expect(mismatch.error).toContain("TLS pinning failed");
  }, 30_000);
});
