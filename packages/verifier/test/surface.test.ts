/**
 * The public surface of the verifier package: exactly the names the surface
 * specification lists, with the shapes callers rely on. A name added or
 * removed by accident fails here.
 */
import { describe, expect, it } from "vitest";
import * as surface from "../src/index.js";
import { INTEL_SGX_ROOT_CA_PEM } from "../src/trust/intel-sgx-root.js";
import { pemBlocks } from "../src/internal/x509/der.js";
import { verificationOf } from "../src/verification.js";

/** Every runtime export, sorted. Type-only exports are checked by compiling this file. */
const EXPORTS = [
  // verifier and verification
  "Verifier",
  "Verification",
  "cryptoMaterialData",
  "parseReference",
  "certPubkeyFP",
  "PUBLIC_REGISTRY_ID",
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
  "formatMeasurement",
].sort();

const VERIFIER_METHODS = ["verifyV3", "verifyV3At", "checkRepoVerifiability"].sort();
/** The policy a verifier carries as own properties, in declaration order. */
const VERIFIER_PROPERTIES = ["freshnessMaxAgeMs", "pinnedRegisters", "callerAuthorizesConfig"];
/** The facts a verification carries as own properties, in declaration order. */
const VERIFICATION_PROPERTIES = [
  "codeDigest",
  "codeTag",
  "configRepo",
  "codeMeasurement",
  "enclaveMeasurement",
  "cryptoMaterial",
  "config",
  "runtime",
  "platform",
  "freshnessExpiresAt",
  "metadata",
];
const VERIFICATION_GETTERS = ["tlsPublicKeyFP", "hpkePublicKey"].sort();
const VERIFICATION_METHODS = ["cryptoMaterialData", "toJSON"].sort();

/** The type-only exports, pinned under the test typecheck: a removed or renamed type fails compilation here. */
type TypeExports = [
  surface.VerifierOptions,
  surface.EmbeddedReferences,
  surface.EmbeddedConfigBytes,
  surface.EmbeddedConfigReference,
  surface.RuntimeReference,
  surface.ConfigVerification,
  surface.ArtifactVerification,
  surface.VerificationMetadata,
  surface.VerificationJSON,
  surface.MeasurementJSON,
  surface.ConfigVerificationJSON,
  surface.ArtifactVerificationJSON,
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

const descriptorsOf = (cls: { prototype: object }): [string, PropertyDescriptor][] =>
  Object.getOwnPropertyNames(cls.prototype)
    .filter((n) => n !== "constructor")
    .map((n) => [n, Object.getOwnPropertyDescriptor(cls.prototype, n)!]);
const methodsOf = (cls: { prototype: object }): string[] =>
  descriptorsOf(cls)
    .filter(([, d]) => typeof d.value === "function")
    .map(([n]) => n)
    .sort();
const gettersOf = (cls: { prototype: object }): string[] =>
  descriptorsOf(cls)
    .filter(([, d]) => d.get !== undefined)
    .map(([n]) => n)
    .sort();

/**
 * Only the verifier builds these: the constructors are private, so a caller
 * who tries fails to compile. Never called; the directives pin the errors
 * under the test typecheck. Untyped construction is refused at runtime,
 * which the surface test checks.
 */
function privateConstructors(): void {
  // @ts-expect-error The constructor is private; a verification comes from a verifier.
  new surface.Verification({} as never);
  // @ts-expect-error The constructor is private; a verifier comes from Verifier.create.
  new surface.Verifier({} as never);
}
void privateConstructors;

/** A verification with the fewest facts, built through the verifier's internal seam. */
const verification = (): surface.Verification =>
  verificationOf({
    codeDigest: "",
    codeTag: "",
    configRepo: "",
    codeMeasurement: { platform: "sev-snp" },
    enclaveMeasurement: { platform: "sev-snp", launch: new Uint8Array(surface.REGISTER_SIZE) },
    cryptoMaterial: [],
    metadata: { verifier: { name: "", version: "" }, verifiedAt: new Date(0) },
  });

describe("public surface", () => {
  it("exports exactly the specified names", () => {
    expect(Object.keys(surface).sort()).toEqual(EXPORTS);
  });

  it("shapes the verifier and the verification as specified", () => {
    expect(typeof surface.Verifier.create).toBe("function");
    expect(Object.getOwnPropertyNames(surface.Verifier).filter((n) => !["length", "name", "prototype"].includes(n))).toEqual(["create"]);
    expect(methodsOf(surface.Verifier)).toEqual(VERIFIER_METHODS);
    expect(gettersOf(surface.Verifier)).toEqual([]);
    expect(methodsOf(surface.Verification)).toEqual(VERIFICATION_METHODS);
    expect(gettersOf(surface.Verification)).toEqual(VERIFICATION_GETTERS);
    expect(Object.keys(verification())).toEqual(VERIFICATION_PROPERTIES);
    expect(surface.NONCE_SIZE).toBe(32);
    expect(surface.REGISTER_SIZE).toBe(48);
    expect(surface.randomNonce()).toHaveLength(32);
    expect(surface.CRYPTO_MATERIAL_ID_TLS).toBe("tls");
    expect(surface.CRYPTO_MATERIAL_ID_HPKE).toBe("hpke");
  });

  it("refuses untyped construction of a verifier or a verification", () => {
    expect(() => new (surface.Verifier as any)({ serverURL: "https://x", configRepo: "org/repo" })).toThrow(surface.UsageError);
    expect(() => new (surface.Verifier as any)({})).toThrow(/Verifier.create/);
    expect(() => new (surface.Verification as any)(verification())).toThrow(surface.UsageError);
    expect(() => new (surface.Verification as any)({})).toThrow(/comes from a verifier/);
  });

  it("builds a default verifier through the public entry", async () => {
    const v = await surface.Verifier.create();
    expect(v).toBeInstanceOf(surface.Verifier);
    expect(Object.keys(v)).toEqual(VERIFIER_PROPERTIES);
    expect(v.freshnessMaxAgeMs).toBe(7 * 24 * 60 * 60 * 1000);
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

  it("parses measurements and reports a bad register as a usage error carrying the original", () => {
    const hex = "ab".repeat(surface.REGISTER_SIZE);
    expect(surface.registerHex(surface.parseRegister(hex.toUpperCase()))).toBe(hex);
    expect(surface.parseExpectedSevSnp("")).toEqual({ platform: "sev-snp", launch: undefined });
    expect(surface.parseExpectedTdx(hex, "", "", "", "")).toEqual({ platform: "tdx", mrtd: surface.parseRegister(hex), rtmr0: undefined, rtmr1: undefined, rtmr2: undefined, rtmr3: undefined });
    const failures: [() => unknown, string][] = [
      [() => surface.parseRegister("zz"), `register must be ${2 * surface.REGISTER_SIZE} hex characters, got 2`],
      [() => surface.parseRegister("g".repeat(2 * surface.REGISTER_SIZE)), "register is not hex"],
      [() => surface.parseExpectedSevSnp("zz"), `Launch: register must be ${2 * surface.REGISTER_SIZE} hex characters, got 2`],
      [() => surface.parseExpectedTdx(hex, "", "zz", "", ""), `RTMR1: register must be ${2 * surface.REGISTER_SIZE} hex characters, got 2`],
    ];
    for (const [parse, message] of failures) {
      let thrown: unknown;
      try {
        parse();
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(surface.UsageError);
      expect(thrown).toBeInstanceOf(surface.VerifyError);
      const usage = thrown as surface.UsageError;
      expect(usage.message).toBe(`usage error: ${message}`);
      expect(usage.cause).toBeInstanceOf(Error);
      expect((usage.cause as Error).message).toBe(message);
      expect(usage.cause).not.toBeInstanceOf(surface.VerifyError);
    }
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
