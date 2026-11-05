import { describe, expect, it } from "vitest";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT } from "../src/document/document.js";
import type { ExpectedTdx, SevSnpMeasurement } from "../src/measurement.js";
import { cryptoMaterialData, Verification, type VerificationFields } from "../src/verification.js";

const reg = (fill: number) => new Uint8Array(48).fill(fill);
const AT = new Date("2026-01-02T03:04:05Z");

function fields(): { fields: VerificationFields; launch: Uint8Array; rtmr1: Uint8Array } {
  const launch = reg(1);
  const rtmr1 = reg(2);
  return {
    launch,
    rtmr1,
    fields: {
      codeDigest: "d",
      codeTag: "v1.0.0",
      configRepo: "tinfoilsh/repo",
      codeMeasurement: { platform: "tdx", rtmr1 },
      enclaveMeasurement: { platform: "sev-snp", launch },
      cryptoMaterial: [
        { id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "fp" },
        { id: "hpke", format: KEY_X25519_HPKE_V1_FORMAT, data: "hpke" },
        { id: "tls", format: "https://example.invalid/other", data: "other" },
      ],
      config: { source: "endorsement", name: "/o/p/r1", digest: "c", reference: "sha256:c", signingKeyHint: "h", approvalTime: AT, scope: "", signatureTime: AT },
      runtime: { source: "endorsement", repo: "tinfoilsh/cvmimage", tag: "v1.2.3", digest: "r", name: "m", commit: "0".repeat(40), approvalTime: AT },
      freshnessExpiresAt: AT,
      metadata: { verifier: { name: "n", version: "v" }, verifiedAt: AT },
    },
  };
}

function makeVerification() {
  const f = fields();
  return { v: new Verification(f.fields), launch: f.launch, rtmr1: f.rtmr1 };
}

describe("Verification", () => {
  it("does not alias the registers it was built from", () => {
    const { v, launch, rtmr1 } = makeVerification();
    launch.fill(0xff);
    rtmr1.fill(0xff);
    expect((v.enclaveMeasurement() as SevSnpMeasurement).launch).toEqual(reg(1));
    expect((v.codeMeasurement() as ExpectedTdx).rtmr1).toEqual(reg(2));
  });

  it("returns copies that callers cannot use to change it", () => {
    const { v } = makeVerification();
    (v.enclaveMeasurement() as SevSnpMeasurement).launch.fill(0xff);
    (v.codeMeasurement() as ExpectedTdx).rtmr1!.fill(0xff);
    (v.cryptoMaterial()[0] as { data: string }).data = "changed";
    v.freshnessExpiresAt()!.setFullYear(1999);
    v.metadata().verifiedAt.setFullYear(1999);
    v.config()!.approvalTime!.setFullYear(1999);
    v.config()!.signatureTime!.setFullYear(1999);
    expect((v.enclaveMeasurement() as SevSnpMeasurement).launch).toEqual(reg(1));
    expect((v.codeMeasurement() as ExpectedTdx).rtmr1).toEqual(reg(2));
    expect(v.cryptoMaterial()[0]!.data).toBe("fp");
    expect(v.freshnessExpiresAt()).toEqual(AT);
    expect(v.metadata().verifiedAt).toEqual(AT);
    expect(v.config()!.approvalTime).toEqual(AT);
    expect(v.config()!.signatureTime).toEqual(AT);
  });

  it("keeps unset expected registers unset", () => {
    const { v } = makeVerification();
    const e = v.codeMeasurement() as ExpectedTdx;
    expect(e.mrtd).toBeUndefined();
    expect(e.rtmr0).toBeUndefined();
  });

  it("exposes its facts only through accessors", () => {
    const { v } = makeVerification();
    expect(Object.keys(v)).toEqual([]);
    expect(v.codeDigest()).toBe("d");
    expect(v.codeTag()).toBe("v1.0.0");
    expect(v.configRepo()).toBe("tinfoilsh/repo");
    expect(v.config()?.name).toBe("/o/p/r1");
    expect(v.runtime()?.tag).toBe("v1.2.3");
    expect(v.platform()).toBeUndefined();
    expect(v.metadata()).toEqual({ verifier: { name: "n", version: "v" }, verifiedAt: AT });
  });

  it("reads the channel keys from the endorsed crypto material by id and format", () => {
    const { v } = makeVerification();
    expect(v.tlsPublicKeyFP()).toBe("fp");
    expect(v.hpkePublicKey()).toBe("hpke");
    expect(v.cryptoMaterialData("tls", "https://example.invalid/other")).toBe("other");
    expect(v.cryptoMaterialData("tls", "https://example.invalid/none")).toBeUndefined();
    expect(cryptoMaterialData([], "tls", KEY_SPKI_FP_SHA256_V1_FORMAT)).toBeUndefined();
    const f = fields().fields;
    const none = new Verification({ ...f, cryptoMaterial: [{ id: "tls", format: "https://example.invalid/other", data: "x" }] });
    expect(none.tlsPublicKeyFP()).toBeUndefined();
    expect(none.hpkePublicKey()).toBeUndefined();
  });

  it("leaves optional facts undefined when not established", () => {
    const f = fields().fields;
    const v = new Verification({ ...f, config: undefined, runtime: undefined, freshnessExpiresAt: undefined });
    expect(v.config()).toBeUndefined();
    expect(v.runtime()).toBeUndefined();
    expect(v.freshnessExpiresAt()).toBeUndefined();
  });
});
