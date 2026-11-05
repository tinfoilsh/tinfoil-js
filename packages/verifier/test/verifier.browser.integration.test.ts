import { describe, it, expect } from "vitest";
import {
  Verifier,
  fetchAttestationDocument,
  randomNonce,
} from "../src/index.js";
const env = (import.meta as any).env ?? {},
  endpoint = env.VITE_TINFOIL_TEST_ENDPOINT,
  identity = env.VITE_TINFOIL_TEST_IDENTITY;
describe.skipIf(!endpoint || !identity)(
  "deployed browser v3 verification",
  () => {
    it("acquires and verifies a nonce-bound document", async () => {
      const nonce = randomNonce();
      const result = await new Verifier().verify(
        await fetchAttestationDocument(endpoint, nonce),
        nonce,
        identity,
      );
      expect(result.freshnessExpiresAt!.getTime()).toBeGreaterThan(Date.now());
      expect(result.tlsPublicKeyFingerprint()).toMatch(/^[0-9a-f]{64}$/);
      expect(result.hpkePublicKey()).toMatch(/^[0-9a-f]{64}$/);
    }, 30000);
  },
);
