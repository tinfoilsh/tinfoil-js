import { describe, it, expect } from "vitest";
import {
  Verifier,
  VerificationError,
  UsageError,
  randomNonce,
} from "../src/index.js";
import "./core-v3.test.js";
import "./sigstore-v3.test.js";
import "./core-policy-v3.test.js";
import "./approval-v3.test.js";
describe("portable browser verifier", () => {
  it("uses native cryptographic randomness and rejects evidence offline", async () => {
    const nonce = randomNonce();
    expect(nonce).toHaveLength(32);
    expect(crypto.subtle).toBeDefined();
    await expect(
      new Verifier().verify(
        new TextEncoder().encode("{}"),
        nonce,
        "tinfoilsh/example",
      ),
    ).rejects.toBeInstanceOf(VerificationError);
    await expect(
      new Verifier().verify(
        new Uint8Array(),
        new Uint8Array(0),
        "tinfoilsh/example",
      ),
    ).rejects.toBeInstanceOf(UsageError);
  });
});
