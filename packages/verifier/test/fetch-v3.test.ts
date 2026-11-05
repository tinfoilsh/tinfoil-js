import { describe, it, expect, vi } from "vitest";
import { fetchAttestationDocument, UsageError } from "../src/index.js";
describe("separate v3 acquisition", () => {
  it("performs one request with caller nonce and returns untrusted bytes", async () => {
    const fetch = vi.fn(async () => new Response(new Uint8Array([1, 2, 3])));
    const nonce = new Uint8Array(32).fill(0xab);
    const bytes = await fetchAttestationDocument(
      "https://enclave.example/some-path?old=1",
      nonce,
      { fetch },
    );
    expect([...bytes]).toEqual([1, 2, 3]);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.href).toBe(
      "https://enclave.example/.well-known/tinfoil-attestation?nonce=" +
        "ab".repeat(32),
    );
    expect(init.redirect).toBe("error");
    expect(init.cache).toBe("no-store");
  });
  it("rejects invalid inputs before networking and never retries acquisition", async () => {
    const fetch = vi.fn(async () => new Response("", { status: 503 }));
    await expect(
      fetchAttestationDocument("http://example.test", new Uint8Array(32), {
        fetch,
      }),
    ).rejects.toBeInstanceOf(UsageError);
    expect(fetch).not.toHaveBeenCalled();
    await expect(
      fetchAttestationDocument("https://example.test", new Uint8Array(32), {
        fetch,
      }),
    ).rejects.toThrow("503");
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

it("cancels HTTP error bodies while preserving the HTTP failure", async () => {
  const cancel = vi.fn(() => { throw new Error("cancel failed"); });
  const response = new Response(new ReadableStream({ cancel }), { status: 503 });
  await expect(fetchAttestationDocument("https://enclave.test", new Uint8Array(32), { fetch: async () => response })).rejects.toThrow("HTTP 503");
  expect(cancel).toHaveBeenCalledTimes(1);
});
it("bounds streamed bodies even without a trustworthy Content-Length", async () => {
  const limit = 32 * 1024 * 1024;
  for (const headers of [{}, { "content-length": "1" }]) {
    const cancel = vi.fn();
    const chunk = new Uint8Array(1024 * 1024);
    let pulls = 0;
    const response = new Response(new ReadableStream({ pull(controller) { pulls++; controller.enqueue(chunk); }, cancel }, { highWaterMark: 0 }), { headers });
    await expect(fetchAttestationDocument("https://enclave.test", new Uint8Array(32), { fetch: async () => response })).rejects.toThrow("size limit");
    expect(pulls).toBe(limit / chunk.length + 1);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(response.body?.locked).toBe(false);
  }
});
it("accepts exactly the document limit and rejects oversized declared bodies without reading", async () => {
  const limit = 32 * 1024 * 1024;
  const accepted = await fetchAttestationDocument("https://enclave.test", new Uint8Array(32), {
    fetch: async () => new Response(new Uint8Array(limit)),
  });
  expect(accepted.length).toBe(limit);
  const pull = vi.fn(), cancel = vi.fn();
  const response = new Response(new ReadableStream({ pull, cancel }, { highWaterMark: 0 }), { headers: { "content-length": String(limit + 1) } });
  await expect(fetchAttestationDocument("https://enclave.test", new Uint8Array(32), { fetch: async () => response })).rejects.toThrow("size limit");
  expect(pull).not.toHaveBeenCalled();
  expect(cancel).toHaveBeenCalledTimes(1);
});
