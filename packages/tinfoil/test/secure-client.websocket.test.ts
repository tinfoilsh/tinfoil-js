import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "events";

const MOCK_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const MOCK_FINGERPRINT = "ab".repeat(32);

const verifyMock = vi.fn(async () => ({
  codeDigest: "test-digest",
  codeTag: "test-release",
  codeMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: ["ab".repeat(48)] },
  enclaveMeasurement: { type: MOCK_MEASUREMENT_TYPE, registers: ["ab".repeat(48)] },
  cryptoMaterial: [
    { id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: MOCK_FINGERPRINT },
    { id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: "mock-hpke-public-key" },
  ],
}));

vi.mock("../src/verifier.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/verifier.js")>();
  return {
    ...original,
    fetchAttestation: vi.fn(async () => new Uint8Array([1, 2, 3])),
    verifyDocumentV3: () => verifyMock(),
  };
});

vi.mock("../src/secure-fetch.js", () => ({
  createSecureFetch: vi.fn(async () => ({
    fetch: vi.fn(),
    getSessionRecoveryToken: vi.fn(),
  })),
}));

vi.mock("../src/atc.js", () => ({
  fetchAttestationBundle: vi.fn(async () => ({
    domain: "enclave.example.com",
    enclaveAttestationReport: { format: "test", body: "test" },
    digest: "test-digest",
    sigstoreBundle: {},
    vcek: "test-vcek",
  })),
  fetchRouter: vi.fn(async () => "enclave.example.com"),
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
import { AttestationError } from "../src/verifier.js";
import { fetchRouter } from "../src/atc.js";

beforeEach(() => {
  createPinnedWebSocketMock.mockClear();
  vi.mocked(fetchRouter).mockClear();
  // Pin the user cache secret so client init never touches ~/.tinfoil.
  vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "test-secret");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("SecureClient.createWebSocket", () => {
  it("connects to the enclave with the attested fingerprint", async () => {
    const client = new SecureClient();
    await client.createWebSocket("/v1/realtime?model=test-model");

    expect(createPinnedWebSocketMock).toHaveBeenCalledWith(
      "wss://enclave.example.com/v1/realtime?model=test-model",
      MOCK_FINGERPRINT,
      undefined,
    );
  });

  it("forwards protocols and wsOptions", async () => {
    const client = new SecureClient();
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
    const client = new SecureClient();
    await expect(
      client.createWebSocket("wss://evil.example.com/v1/realtime"),
    ).rejects.toThrow(/bound to the verified enclave/);
    expect(createPinnedWebSocketMock).not.toHaveBeenCalled();
  });

  it("re-attests after a TLS pin failure", async () => {
    const client = new SecureClient();
    const socket = await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchRouter).toHaveBeenCalledTimes(1);

    // A stale pin (enclave rotated its TLS key) surfaces as an `error` event;
    // the client should drop its cached attestation so the next call re-attests.
    socket.emit(
      "error",
      new AttestationError(
        "TLS pinning failed: Server certificate public key does not match the attested key",
      ),
    );

    await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchRouter).toHaveBeenCalledTimes(2);
  });

  it("keeps the cached attestation on an unrelated socket error", async () => {
    const client = new SecureClient();
    const socket = await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchRouter).toHaveBeenCalledTimes(1);

    socket.emit("error", new Error("ECONNRESET"));

    await client.createWebSocket("/v1/realtime?model=test-model");
    expect(fetchRouter).toHaveBeenCalledTimes(1);
  });
});

describe("SecureClient.getPinnedWebSocketOptions", () => {
  it("returns pinned options for the attested fingerprint", async () => {
    const client = new SecureClient();
    const options = await client.getPinnedWebSocketOptions();

    expect(pinnedWsClientOptionsMock).toHaveBeenCalledWith(MOCK_FINGERPRINT);
    expect(options).toEqual({ rejectUnauthorized: true });
  });

  it("returns pinned options when a proxy baseURL is configured", async () => {
    const client = new SecureClient({
      baseURL: "https://proxy.example.com/v1/",
    });
    await expect(client.getPinnedWebSocketOptions()).resolves.toEqual({
      rejectUnauthorized: true,
    });
    expect(pinnedWsClientOptionsMock).toHaveBeenCalledWith(MOCK_FINGERPRINT);
  });
});
