import { describe, expect, it } from "vitest";
import { serializeSessionRecoveryToken } from "ehbp";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch.js";
import { ConfigurationError } from "../src/errors.js";
// @ts-expect-error The Vite plugin publishes the local test server's key and origin.
import relay, { publicKey } from "virtual:tinfoil-browser-relay";
describe("actual browser authenticated EHBP stream cancellation", () => {
  it("cancels the encrypted socket stream and retains its recovery token until a new request starts", async () => {
    const transport = createEncryptedBodyFetch(relay, publicKey);
    const id = crypto.randomUUID();
    const response = await transport.fetch(`/session-stream?id=${id}`, { method: "POST", body: "private cancellation request" });
    const token = serializeSessionRecoveryToken(await transport.getSessionRecoveryToken());
    const reader = response.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("authenticated first frame");
    await reader.cancel("stop browser consumer"); reader.releaseLock();
    // Browser stream cancellation can resolve before the server observes the
    // socket closing. Use a network deadline instead of poll's one-second default.
    await expect.poll(async () => (await (await fetch(`${relay}/session-state?id=${id}`, { cache: "no-store" })).json())?.closed,
      { timeout: 10_000 }).toBe(true);
    const state = await (await fetch(`${relay}/session-state?id=${id}`)).json();
    expect(state.plaintext).toBe("private cancellation request");
    expect(serializeSessionRecoveryToken(await transport.getSessionRecoveryToken())).toBe(token);
    await (await transport.fetch("/allowed", { method: "POST", body: "next request" })).body?.cancel();
    await expect(transport.getSessionRecoveryToken()).rejects.toBeInstanceOf(ConfigurationError);
  });
});
