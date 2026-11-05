import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "events";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const MOCK_FINGERPRINT = "ab".repeat(32);

const verifyMock = vi.fn(async () => ({
  tlsPublicKeyFingerprint: () => MOCK_FINGERPRINT,
  hpkePublicKey: () => "mock-hpke-public-key",
  freshnessExpiresAt: new Date(Date.now() + 60_000),
  measurement: { type: MOCK_MEASUREMENT_TYPE, registers: [] },
}));

vi.mock("@tinfoilsh/verifier", async (importOriginal) => {
  const original = await importOriginal<typeof import("@tinfoilsh/verifier")>();
  return {
    ...original,
    Verifier: class {
      verify() {
        return verifyMock();
      }
    },
  };
});

vi.mock("../src/secure-fetch.js", () => ({
  createSecureFetch: vi.fn(async () => ({
    fetch: vi.fn(),
    getSessionRecoveryToken: vi.fn(),
  })),
}));

vi.mock("../src/acquisition.js", async original => ({
  ...await original<object>(),
  fetchAttestationDocument: vi.fn(async () => new Uint8Array([1])),
}));

const createPinnedWebSocketMock = vi.fn(async () => new EventEmitter());
const pinnedWsClientOptionsMock = vi.fn(async () => ({
  rejectUnauthorized: true,
}));

vi.mock("../src/pinned-ws.js", () => ({
  createPinnedWebSocket: createPinnedWebSocketMock,
  pinnedWsClientOptions: pinnedWsClientOptionsMock,
}));

import { SecureClient } from "../src/secure-client.js";
import { bindingError } from "../src/errors.js";
import { fetchAttestationDocument } from "../src/acquisition.js";

beforeEach(() => {
  createPinnedWebSocketMock.mockClear();
  vi.mocked(fetchAttestationDocument).mockClear();
  // Pin the user cache secret so client init never touches ~/.tinfoil.
  vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "test-secret");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

const clientOptions = { enclaveURL: "https://enclave.example.com", configRepo: "tinfoilsh/workload" };

describe("SecureClient.createWebSocket", () => {
  it("connects to the enclave with the attested fingerprint", async () => {
    const client = new SecureClient(clientOptions);
    await client.createWebSocket("/v1/realtime?model=test-model");

    expect(createPinnedWebSocketMock).toHaveBeenCalledWith(
      "wss://enclave.example.com/v1/realtime?model=test-model",
      MOCK_FINGERPRINT,
      undefined,
    );
  });

  it("forwards protocols and wsOptions", async () => {
    const client = new SecureClient(clientOptions);
    const options = {
      protocols: ["realtime"],
      wsOptions: { headers: { Authorization: "Bearer k" } },
    };
    await client.createWebSocket("/v1/realtime?model=test-model", options);

    expect(createPinnedWebSocketMock).toHaveBeenCalledWith(
      expect.any(String),
      MOCK_FINGERPRINT,
      options,
    );
  });

  it("connects directly to the enclave when a proxy baseURL is configured", async () => {
    const client = new SecureClient({
      enclaveURL: "https://enclave.example.com", configRepo: "tinfoilsh/workload",
      baseURL: "https://proxy.example.com/v1/",
    });
    await client.createWebSocket("/v1/realtime");

    expect(createPinnedWebSocketMock).toHaveBeenCalledWith(
      "wss://enclave.example.com/v1/realtime",
      MOCK_FINGERPRINT,
      undefined,
    );
  });

  it("rejects absolute URLs pointing at another host", async () => {
    const client = new SecureClient(clientOptions);
    await expect(
      client.createWebSocket("wss://evil.example.com/v1/realtime"),
    ).rejects.toThrow(/direct verified enclave/);
    expect(createPinnedWebSocketMock).not.toHaveBeenCalled();
  });

  it("re-attests after a TLS pin failure", async () => {
    const client = new SecureClient(clientOptions);
    const socket = await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchAttestationDocument).toHaveBeenCalledTimes(1);

    // A stale pin (enclave rotated its TLS key) surfaces as an `error` event;
    // the client should drop its cached attestation so the next call re-attests.
    socket.emit(
      "error",
      bindingError(
        "TLS pinning failed: Server certificate public key does not match the attested key",
      ),
    );

    await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchAttestationDocument).toHaveBeenCalledTimes(2);
  });

  it("keeps the cached attestation on an unrelated socket error", async () => {
    const client = new SecureClient(clientOptions);
    const socket = await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchAttestationDocument).toHaveBeenCalledTimes(1);

    socket.emit("error", new Error("ECONNRESET"));

    await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchAttestationDocument).toHaveBeenCalledTimes(1);
  });
});

describe("SecureClient.getPinnedWebSocketOptions", () => {
  it("returns pinned options for the attested fingerprint", async () => {
    const client = new SecureClient(clientOptions);
    const options = await client.getPinnedWebSocketOptions();

    expect(pinnedWsClientOptionsMock).toHaveBeenCalledWith(MOCK_FINGERPRINT);
    expect(options).toEqual({ rejectUnauthorized: true });
  });

  it("returns pinned options when a proxy baseURL is configured", async () => {
    const client = new SecureClient({
      enclaveURL: "https://enclave.example.com", configRepo: "tinfoilsh/workload",
      baseURL: "https://proxy.example.com/v1/",
    });
    await expect(client.getPinnedWebSocketOptions()).resolves.toEqual({
      rejectUnauthorized: true,
    });
    expect(pinnedWsClientOptionsMock).toHaveBeenCalledWith(MOCK_FINGERPRINT);
  });
});
