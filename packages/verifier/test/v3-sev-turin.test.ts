// Synthetic AMD SEV-SNP Turin (#115) acceptance + negatives, proving the JS
// v3 verifier verifies a Turin platform the way tinfoil-python/go do. The
// conformance suite carries only Genoa fixtures, so these exercise the Turin
// paths (per-product roots, TCB struct v1, 8-byte HWID, iommu_write_safe,
// fmc_spl) with REAL crypto: the material in fixtures/v3-sev-turin.json is a
// genuinely-signed ARK->ASK->VCEK chain + report + CRL minted by
// tinfoil-python tests/v3/sevsynth.py (mirrored recipe), and the verifier does
// real ECDSA-P384 / RSA-PSS-SHA384 verification against it — no mocks.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { parseDocument } from "../src/v3/envelope.js";
import { VerificationError } from "../src/v3/errors.js";
import type { SEVSNPPolicy } from "../src/v3/policy.js";
import { sevAssemble, sevAuthenticate, sevValidate, type SevQuote } from "../src/v3/sev/index.js";

interface Case {
  doc_b64: string;
  root_pem: string;
  chip_id_hex: string;
  measurement_hex: string;
}
interface Fixture {
  now_iso: string;
  launch_digest_hex: string;
  report_data_hex: string;
  cases: Record<string, Case>;
}

const fx: Fixture = JSON.parse(readFileSync(join(__dirname, "fixtures", "v3-sev-turin.json"), "utf-8"));
const NOW = new Date(fx.now_iso);

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
const b64ToBytes = (b64: string): Uint8Array => Uint8Array.from(Buffer.from(b64, "base64"));
const LAUNCH_DIGEST = hexToBytes(fx.launch_digest_hex);
const REPORT_DATA = hexToBytes(fx.report_data_hex);

// makePolicy mirrors tinfoil-python tests/v3/sevsynth make_policy: a policy
// matching sevsynth's default report for the product line.
function makePolicy(product: "Genoa" | "Turin", over: Partial<SEVSNPPolicy> = {}): SEVSNPPolicy {
  const fmc = product === "Turin" ? 1 : undefined;
  return {
    minimumBuild: 21,
    minimumAPIVersion: "1.55",
    minimumABIVersion: "0.0",
    minimumGuestSVN: 0,
    minimumTCB: { fmcSpl: fmc, blSpl: 7, teeSpl: 0, snpSpl: 20, ucodeSpl: 72 },
    minimumLaunchTCB: { fmcSpl: fmc, blSpl: 7, teeSpl: 0, snpSpl: 20, ucodeSpl: 72 },
    guestPolicy: {
      debug: false,
      smt: true,
      migrateMA: false,
      singleSocket: false,
      cxlAllowed: false,
      memAES256XTS: false,
      raplDis: false,
      ciphertextHidingDRAM: false,
      pageSwapDisable: false,
    },
    platformInfo: {
      smtEnabled: false,
      tsmeEnabled: false,
      eccEnabled: false,
      raplDisabled: false,
      ciphertextHidingDRAM: false,
      aliasCheckComplete: false,
      iommuWriteSafe: product === "Turin",
      tioEnabled: false,
    },
    permitProvisionalFirmware: false,
    vmpl: 0,
    hostData: "00".repeat(32),
    imageID: "00".repeat(16),
    familyID: "00".repeat(16),
    requireAuthorKey: false,
    requireIDBlock: false,
    minimumLaunchMitigationVector: 0,
    minimumCurrentMitigationVector: 0,
    ...over,
  };
}

function authenticate(name: string): Promise<SevQuote> {
  const c = fx.cases[name];
  return sevAuthenticate(parseDocument(b64ToBytes(c.doc_b64)), { rootPEM: c.root_pem, now: NOW });
}

// validate runs the full authenticate -> assemble -> validate path.
async function validate(name: string, product: "Genoa" | "Turin", policy?: SEVSNPPolicy): Promise<SevQuote> {
  const q = await authenticate(name);
  const e = sevAssemble(policy ?? makePolicy(product), q, LAUNCH_DIGEST, REPORT_DATA);
  sevValidate(e, q);
  return q;
}

async function expectLayer(fn: () => Promise<unknown>, layer: string): Promise<void> {
  await expect(fn()).rejects.toMatchObject({ layer });
  await expect(fn()).rejects.toBeInstanceOf(VerificationError);
}

describe("v3 SEV-SNP Turin (#115)", () => {
  // --- acceptance ------------------------------------------------------------
  it("accepts a valid Turin platform end to end", async () => {
    const q = await validate("turin", "Turin");
    expect(q.productLine).toBe("Turin");
    expect(q.identity).toBe(fx.cases.turin.chip_id_hex);
    expect(q.measurement.registers[0]).toBe(fx.cases.turin.measurement_hex);
  });

  it("still accepts a valid Genoa platform (byte-compatible control)", async () => {
    const q = await validate("genoa", "Genoa");
    expect(q.productLine).toBe("Genoa");
    expect(q.identity).toBe(fx.cases.genoa.chip_id_hex);
  });

  // --- A1: per-product root selection ---------------------------------------
  it("selects the embedded Turin root (no override) and reaches chain verification", async () => {
    // With no rootPEM override the verifier must pick the embedded Turin chain
    // rather than hard-rejecting the product line; the synthetic VCEK is not
    // signed by the real AMD Turin ASK, so the chain check rejects at QUOTE.
    const doc = parseDocument(b64ToBytes(fx.cases.turin.doc_b64));
    await expectLayer(() => sevAuthenticate(doc, { now: NOW }), "QUOTE_REJECTED");
  });

  it("rejects a Turin report signed under a rogue anchor", async () => {
    await expectLayer(() => validate("turin_rogue", "Turin"), "QUOTE_REJECTED");
  });

  // --- A3: KDS cert struct version ------------------------------------------
  it("rejects an unsupported VCEK TCB struct version (not 0 or 1)", async () => {
    await expectLayer(() => authenticate("turin_cert_v2"), "QUOTE_REJECTED");
  });

  // --- A2: Turin TCB layout / reserved bits ---------------------------------
  it("rejects non-zero reserved bits in a Turin REPORTED_TCB", async () => {
    await expectLayer(() => validate("turin_reserved_tcb", "Turin"), "POLICY_REJECTED");
  });

  // --- A4: 8-byte PSN CHIP_ID binding ---------------------------------------
  it("rejects a Turin CHIP_ID that does not match the 8-byte VCEK HWID", async () => {
    await expectLayer(() => validate("turin_hwid33", "Turin"), "POLICY_REJECTED");
  });

  // --- A5: iommu_write_safe (PLATFORM_INFO bit 6) ---------------------------
  it("rejects a Turin report whose PLATFORM_INFO lacks the required iommu_write_safe", async () => {
    await expectLayer(() => validate("turin_pi_missing", "Turin"), "POLICY_REJECTED");
  });

  // --- A5 / fmc: per-product policy rules (pure policy, valid quote) ---------
  it("rejects a Turin policy without iommu_write_safe", async () => {
    const q = await authenticate("turin");
    const p = makePolicy("Turin");
    p.platformInfo.iommuWriteSafe = false;
    expect(() => sevAssemble(p, q, LAUNCH_DIGEST, REPORT_DATA)).toThrow(/iommu_write_safe is required/);
  });

  it("rejects a Turin policy without fmc_spl", async () => {
    const q = await authenticate("turin");
    const p = makePolicy("Turin");
    p.minimumLaunchTCB = { fmcSpl: undefined, blSpl: 7, teeSpl: 0, snpSpl: 20, ucodeSpl: 72 };
    expect(() => sevAssemble(p, q, LAUNCH_DIGEST, REPORT_DATA)).toThrow(/fmc_spl is required/);
  });

  it("rejects a Genoa policy that sets iommu_write_safe", async () => {
    const q = await authenticate("genoa");
    const p = makePolicy("Genoa");
    p.platformInfo.iommuWriteSafe = true;
    expect(() => sevAssemble(p, q, LAUNCH_DIGEST, REPORT_DATA)).toThrow(/iommu_write_safe is not valid/);
  });

  it("rejects a Genoa policy that sets fmc_spl", async () => {
    const q = await authenticate("genoa");
    const p = makePolicy("Genoa");
    p.minimumTCB = { fmcSpl: 0, blSpl: 7, teeSpl: 0, snpSpl: 20, ucodeSpl: 72 };
    expect(() => sevAssemble(p, q, LAUNCH_DIGEST, REPORT_DATA)).toThrow(/fmc_spl is not valid/);
  });

  // --- Turin fmc_spl participates in TCB floor comparison -------------------
  it("enforces the Turin fmc_spl minimum floor", async () => {
    const p = makePolicy("Turin");
    p.minimumTCB = { fmcSpl: 2, blSpl: 7, teeSpl: 0, snpSpl: 20, ucodeSpl: 72 };
    await expectLayer(() => validate("turin", "Turin", p), "POLICY_REJECTED");
  });
});
