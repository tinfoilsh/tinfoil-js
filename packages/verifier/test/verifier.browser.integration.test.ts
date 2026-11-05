/**
 * The verifier's root entry in a browser against the live service, in
 * Chromium: the page fetches the attestation document with a fresh nonce and
 * verifies it with the embedded production roots and the current time, so
 * the keys the document endorses are proven from a page with WebCrypto alone.
 * Needs the integration lane, compiled into the bundle by the lane's config.
 */
import { describe, expect, it } from "vitest";
import { randomNonce, Verifier } from "../src/index.js";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const HOST = "inference.tinfoil.sh";
const REPO = "tinfoilsh/confidential-model-router";
const SHA256_HEX = /^[0-9a-f]{64}$/;
/** Back-off between attempts when the service rate-limits (HTTP 429), in milliseconds. */
const RETRY_DELAYS_MS = [2_000, 4_000, 8_000];

/** GET the attestation document for `nonce`, retrying a few times with back-off when the service rate-limits. */
async function fetchDocument(nonce: Uint8Array): Promise<Uint8Array> {
  const hex = Array.from(nonce, (b) => b.toString(16).padStart(2, "0")).join("");
  const url = `https://${HOST}/.well-known/tinfoil-attestation?nonce=${hex}`;
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(url);
    if (response.status === 429 && attempt < RETRY_DELAYS_MS.length) {
      await response.body?.cancel();
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAYS_MS[attempt]));
      continue;
    }
    if (!response.ok) throw new Error(`HTTP GET ${url}: ${response.status} ${response.statusText}`);
    return new Uint8Array(await response.arrayBuffer());
  }
}

describe("the verifier in a browser against the live service", () => {
  it.skipIf(!RUN_INTEGRATION)("fetches the attestation document and verifies it with the embedded roots", async () => {
    const nonce = randomNonce();
    const doc = await fetchDocument(nonce);
    const verifier = await Verifier.create();
    const verified = await verifier.verifyV3(doc, nonce, REPO);
    expect(verified.codeDigest()).toMatch(SHA256_HEX);
    expect(verified.tlsPublicKeyFP()).toMatch(SHA256_HEX);
    expect(verified.hpkePublicKey()).toMatch(SHA256_HEX);
  });
});
