/**
 * The public surface of the verifier package: exactly the names the surface
 * specification lists, with the shapes callers rely on. A name added or
 * removed by accident fails here.
 */
import { describe, expect, it } from "vitest";
import * as surface from "../../src/v3/index.js";
import { INTEL_SGX_ROOT_CA_PEM } from "../../src/v3/trust/intel-sgx-root.js";
import { pemBlocks } from "../../src/v3/internal/x509/der.js";

/** Every runtime export, sorted. Type-only exports are checked by compiling this file. */
const EXPORTS = [
  // verifier and verification
  "Verifier",
  "Verification",
  "cryptoMaterialData",
  "parseReference",
  "certPubkeyFP",
  // errors
  "VerifyError",
  "UsageError",
  "VerificationError",
  // document
  "randomNonce",
  "NONCE_SIZE",
  "CRYPTO_MATERIAL_ID_TLS",
  "CRYPTO_MATERIAL_ID_HPKE",
  "ATTESTATION_V3_FORMAT",
  "REPORT_DATA_V1_ALGORITHM",
  "CRYPTO_MATERIAL_V1_FORMAT",
  "DEVICE_EVIDENCE_V1_FORMAT",
  "SEV_SNP_REPORT_V1_FORMAT",
  "TDX_QUOTE_V1_FORMAT",
  "NVIDIA_GPU_EVIDENCE_V1_FORMAT",
  "KEY_SPKI_FP_SHA256_V1_FORMAT",
  "KEY_SPKI_V1_FORMAT",
  "KEY_X25519_HPKE_V1_FORMAT",
  // measurement
  "REGISTER_SIZE",
  "registerHex",
  "parseRegister",
  "parseExpectedSevSnp",
  "parseExpectedTdx",
  "expectedOf",
  "cloneMeasurement",
  "cloneExpected",
  "formatMeasurement",
].sort();

const VERIFIER_METHODS = ["verifyV3", "verifyV3At", "checkRepoVerifiability", "callerAuthorizesConfig", "pinnedRegisters", "freshnessMaxAgeMs"].sort();
const VERIFICATION_METHODS = [
  "codeDigest",
  "codeTag",
  "configRepo",
  "codeMeasurement",
  "enclaveMeasurement",
  "config",
  "runtime",
  "platform",
  "cryptoMaterial",
  "cryptoMaterialData",
  "tlsPublicKeyFP",
  "hpkePublicKey",
  "freshnessExpiresAt",
  "metadata",
].sort();

/** The type-only exports, pinned under the test typecheck: a removed or renamed type fails compilation here. */
type TypeExports = [
  surface.VerifierOptions,
  surface.EmbeddedReferences,
  surface.ConfigVerification,
  surface.ArtifactVerification,
  surface.VerificationMetadata,
  surface.ReferenceSource,
  surface.ConfigEndorsement,
  surface.Layer,
  surface.Reference,
  surface.CryptoMaterialItem,
  surface.Measurement,
  surface.Expected,
  surface.Register,
  surface.SevSnpMeasurement,
  surface.TdxMeasurement,
  surface.ExpectedSevSnp,
  surface.ExpectedTdx,
];
const typeExports: TypeExports | undefined = undefined;
void typeExports;

const methodsOf = (cls: { prototype: object }): string[] =>
  Object.getOwnPropertyNames(cls.prototype)
    .filter((n) => n !== "constructor")
    .sort();

describe("public surface", () => {
  it("exports exactly the specified names", () => {
    expect(Object.keys(surface).sort()).toEqual(EXPORTS);
  });

  it("shapes the verifier and the verification as specified", () => {
    expect(typeof surface.Verifier.create).toBe("function");
    expect(Object.getOwnPropertyNames(surface.Verifier).filter((n) => !["length", "name", "prototype"].includes(n))).toEqual(["create"]);
    expect(methodsOf(surface.Verifier)).toEqual(VERIFIER_METHODS);
    expect(methodsOf(surface.Verification)).toEqual(VERIFICATION_METHODS);
    expect(surface.NONCE_SIZE).toBe(32);
    expect(surface.REGISTER_SIZE).toBe(48);
    expect(surface.randomNonce()).toHaveLength(32);
    expect(surface.CRYPTO_MATERIAL_ID_TLS).toBe("tls");
    expect(surface.CRYPTO_MATERIAL_ID_HPKE).toBe("hpke");
  });

  it("builds a default verifier through the public entry", async () => {
    const v = await surface.Verifier.create();
    expect(v).toBeInstanceOf(surface.Verifier);
    expect(v.freshnessMaxAgeMs()).toBe(7 * 24 * 60 * 60 * 1000);
    await expect(v.verifyV3At(new Uint8Array(), new Uint8Array(32), "org/repo", new Date(Number.NaN))).rejects.toBeInstanceOf(surface.UsageError);
  });

  it("classifies errors under one supertype", () => {
    const usage = new surface.UsageError("bad");
    const rejected = new surface.VerificationError("quote", "bad");
    expect(usage).toBeInstanceOf(surface.VerifyError);
    expect(rejected).toBeInstanceOf(surface.VerifyError);
    expect(rejected.layer).toBe("quote");
    expect(usage.name).toBe("UsageError");
    expect(rejected.name).toBe("VerificationError");
  });

  it("parses references and reports a bad one as a usage error", () => {
    expect(surface.parseReference("tinfoilsh/repo@v1.0.0@sha256:" + "a".repeat(64))).toEqual({ repo: "tinfoilsh/repo", tag: "v1.0.0", digest: "a".repeat(64) });
    expect(surface.parseReference("tinfoilsh/repo")).toEqual({ repo: "tinfoilsh/repo", tag: "", digest: "" });
    expect(() => surface.parseReference("no slash")).toThrow(surface.UsageError);
  });

  it("fingerprints a certificate's public key and reports non-certificates as usage errors", async () => {
    const [root] = pemBlocks(INTEL_SGX_ROOT_CA_PEM, "CERTIFICATE");
    const fp = await surface.certPubkeyFP(root!);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    expect(await surface.certPubkeyFP(root!)).toBe(fp);
    await expect(surface.certPubkeyFP(new Uint8Array([1, 2, 3]))).rejects.toBeInstanceOf(surface.UsageError);
  });
});
