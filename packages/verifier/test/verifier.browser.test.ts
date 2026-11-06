/**
 * The verifier in a browser (Chromium and WebKit): the package root loads
 * without Node built-ins, the embedded trust material and signing keys import
 * through WebCrypto, and the public entry behaves as it does on Node. The
 * fixture-driven suites run on Node only, so this is where a browser-only
 * regression in the module graph or the crypto path shows up.
 */
import { describe, expect, it } from "vitest";
import * as verifier from "../src/index.js";
import { pemBlocks } from "../src/internal/x509/der.js";
import { INTEL_SGX_ROOT_CA_PEM } from "../src/trust/intel-sgx-root.js";

describe("verifier in a browser", () => {
  it("runs in a browser with WebCrypto", () => {
    expect(typeof window).toBe("object");
    expect(typeof crypto.subtle.digest).toBe("function");
  });

  it("builds the default verifier", async () => {
    const v = await verifier.Verifier.create();
    expect(v).toBeInstanceOf(verifier.Verifier);
    expect(v.freshnessMaxAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(v.callerAuthorizesConfig).toBe(false);
    expect(v.pinnedRegisters).toBeUndefined();
  });

  it("rejects bytes that are not an attestation document at the envelope layer", async () => {
    const v = await verifier.Verifier.create();
    const err: unknown = await v.verifyV3(new TextEncoder().encode("{}"), verifier.randomNonce(), "tinfoilsh/confidential-model-router").then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(verifier.VerificationError);
    expect((err as verifier.VerificationError).layer).toBe("envelope");
  });

  it("reports invalid inputs as usage errors", async () => {
    const v = await verifier.Verifier.create();
    await expect(v.verifyV3At(new Uint8Array(), new Uint8Array(verifier.NONCE_SIZE), "org/repo", new Date(Number.NaN))).rejects.toBeInstanceOf(verifier.UsageError);
    expect(() => verifier.parseReference("no slash")).toThrow(verifier.UsageError);
    await expect(verifier.certPubkeyFP(new Uint8Array([1, 2, 3]))).rejects.toBeInstanceOf(verifier.UsageError);
  });

  it("fingerprints a certificate's public key", async () => {
    const [root] = pemBlocks(INTEL_SGX_ROOT_CA_PEM, "CERTIFICATE");
    expect(await verifier.certPubkeyFP(root!)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("parses references and registers", () => {
    expect(verifier.parseReference("tinfoilsh/repo@v1.0.0")).toEqual({ repo: "tinfoilsh/repo", tag: "v1.0.0", digest: "" });
    expect(verifier.randomNonce()).toHaveLength(verifier.NONCE_SIZE);
    const hex = "ab".repeat(verifier.REGISTER_SIZE);
    expect(verifier.registerHex(verifier.parseRegister(hex.toUpperCase()))).toBe(hex);
  });
});
