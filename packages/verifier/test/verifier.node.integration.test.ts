import { describe, it, expect } from "vitest";
import {
  Verifier,
  fetchAttestationDocument,
  randomNonce,
} from "../src/index.js";
const endpoint = process.env.TINFOIL_TEST_ENDPOINT,
  identity = process.env.TINFOIL_TEST_IDENTITY;
describe.skipIf(
  process.env.RUN_TINFOIL_INTEGRATION !== "true" || !endpoint || !identity,
)("deployed v3 verification", () => {
  it("acquires a fresh nonce document and verifies its authenticated lifetime", async () => {
    const nonce = randomNonce();
    const bytes = await fetchAttestationDocument(endpoint!, nonce);
    const result = await new Verifier().verify(bytes, nonce, identity!);
    expect(result.freshnessExpiresAt!.getTime()).toBeGreaterThan(Date.now());
    expect(result.tlsPublicKeyFingerprint()).toMatch(/^[0-9a-f]{64}$/);
    expect(result.hpkePublicKey()).toMatch(/^[0-9a-f]{64}$/);
  }, 30000);
});
