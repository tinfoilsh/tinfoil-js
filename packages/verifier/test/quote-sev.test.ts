/**
 * Tests for the SEV-SNP quote layer: report decoding, TCB layouts, the VCEK
 * shape and extensions, report authentication against the pinned and
 * injected AMD roots, and policy expectations.
 *
 * Report-layout rules are exercised on hand-built reports. Authentication
 * runs on the shared tinfoil-conformance vectors: the captured production
 * document of the real-frozen set under the embedded Genoa roots, and the
 * synthetic quote-sev set under its injected roots. Expectations are checked
 * against the production report with the policy endorsed for its machine.
 * Suites that need the vectors are skipped when the checkout is not available.
 */
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { dangerousTestOnlyDecode } from "../conformance/testing.js";
import { toHex } from "../src/internal/bytes.js";
import { decodeHex, parse as parseArtifact, policyFor } from "../src/internal/policy/artifact.js";
import type { SevSnpPolicy } from "../src/internal/policy/sev.js";
import { authenticate } from "../src/internal/quote/quote.js";
import { assembleSev, authenticateSev, validateSev, type SevQuote } from "../src/internal/quote/sev/authenticate.js";
import { identity } from "../src/internal/quote/sev/identity.js";
import {
  cpuid1EaxOf,
  fmsOf,
  parseGuestPolicy,
  parsePlatformInfo,
  parseReport,
  parseSignerInfo,
  productLine,
  REPORT_SIZE,
  SIGNER_VCEK,
  signatureRaw,
} from "../src/internal/quote/sev/report.js";
import { composeTcb, decomposeTcb, formatTcb, TCB_LAYOUT_0, TCB_LAYOUT_1, tcbLe, type TcbParts } from "../src/internal/quote/sev/tcb.js";
import { checkCertChainShape, checkVcekShape, parseAmdRoots, parseVcekExtensions } from "../src/internal/quote/sev/vcek.js";
import { AMD_GENOA_CERT_CHAIN_PEM } from "../src/trust/amd-genoa-chain.js";
import { AMD_TURIN_CERT_CHAIN_PEM } from "../src/trust/amd-turin-chain.js";
import { parseCertificate, type Certificate } from "../src/internal/x509/certificate.js";
import {
  amdMaterial,
  conformanceAvailable,
  decodeDocument,
  inputBytes,
  loadFixture,
  loadFixtures,
  vectorsTitle,
  type AmdMaterial,
  type ConformanceFixture,
} from "./helpers/conformance.js";

const b64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const unix = (s: number): Date => new Date(s * 1000);
const withoutVectors = !conformanceAvailable();
// Read at module scope: a skipped describe still runs its body.
const sevFixtures = withoutVectors ? [] : loadFixtures("quote-sev");

/** A well-formed version-3 Genoa report with every reserved range zero and no signature. */
function blankReport(): Uint8Array {
  const r = new Uint8Array(REPORT_SIZE);
  const view = new DataView(r.buffer);
  view.setUint32(0x00, 3, true);
  view.setBigUint64(0x08, 1n << 17n, true);
  view.setUint32(0x34, 1, true);
  r[0x188] = 0x19;
  r[0x189] = 0x11;
  r[0x18a] = 0x01;
  return r;
}

/** The injected ASK+ARK PEM a vector names, in the order the roots are pinned. */
function rootsOf(fixture: ConformanceFixture): Uint8Array | undefined {
  const { ask_pem: ask, amd_root_ca_pem: ark } = fixture.input;
  if (ask === undefined || ark === undefined) return undefined;
  return utf8(`${ask.trim()}\n${ark.trim()}\n`);
}

function reportOf(fixture: ConformanceFixture): Uint8Array {
  return b64(decodeDocument(fixture).cpu_evidence.report_base64);
}

// ---------------------------------------------------------------- report layout

describe("sev report", () => {
  it("decodes a blank report and rejects the wrong length", () => {
    const r = parseReport(blankReport());
    expect(r.version).toBe(3);
    expect(r.signatureAlgo).toBe(1);
    expect(r.signer.signingKey).toBe(SIGNER_VCEK);
    expect(r.cpuid1Eax).toBe(0x00a10f11);
    expect(r.signature).toHaveLength(144);
    expect(() => parseReport(blankReport().subarray(1))).toThrow(/exactly 1184 bytes/);
    expect(() => parseReport(new Uint8Array(REPORT_SIZE + 1))).toThrow(/exactly 1184 bytes/);
  });

  it.each([
    [0x4c, "after SIGNER_INFO"],
    [0x18b, "after CPUID"],
    [0x19f, "before CHIP_ID"],
    [0x1eb, "after CURRENT_MAJOR"],
    [0x1ef, "after COMMITTED_MAJOR"],
    [0x208, "before SIGNATURE"],
    [0x29f, "before SIGNATURE"],
    [0x390, "after the ECDSA signature"],
    [0x49f, "at the end"],
  ])("rejects a non-zero reserved byte at 0x%s (%s)", (offset) => {
    const r = blankReport();
    r[offset] = 1;
    expect(() => parseReport(r)).toThrow(/reserved and must be zero/);
  });

  it("reads the mitigation vectors from version 5 on and reserves their bytes before", () => {
    const r = blankReport();
    r[0x1f8] = 0x05;
    r[0x207] = 0x80;
    expect(() => parseReport(r)).toThrow(/0x1f8:0x208 are reserved/);
    new DataView(r.buffer).setUint32(0x00, 4, true);
    expect(() => parseReport(r)).toThrow(/0x1f8:0x208 are reserved/);
    new DataView(r.buffer).setUint32(0x00, 5, true);
    const v5 = parseReport(r);
    expect(v5.launchMitVector).toBe(5n);
    expect(v5.currentMitVector).toBe(1n << 63n);
    r[0x1f8] = r[0x207] = 0;
    new DataView(r.buffer).setUint32(0x00, 3, true);
    expect(parseReport(r)).toMatchObject({ launchMitVector: 0n, currentMitVector: 0n });
  });

  it("reserves the CPUID bytes in a version-2 report", () => {
    const r = blankReport();
    new DataView(r.buffer).setUint32(0x00, 2, true);
    expect(() => parseReport(r)).toThrow(/0x188:0x1a0 are reserved/);
    r[0x188] = r[0x189] = r[0x18a] = 0;
    expect(parseReport(r).cpuid1Eax).toBe(0);
    expect(() => productLine(parseReport(r))).toThrow(/no CPUID product identity \(report version 2, want 3\+\)/);
  });

  it("rejects a report version outside 2 to 5", () => {
    for (const version of [0, 1, 6, 0xffffffff]) {
      const r = blankReport();
      new DataView(r.buffer).setUint32(0x00, version, true);
      expect(() => parseReport(r)).toThrow(new RegExp(`unsupported SEV-SNP report version ${version} \\(want 2 to 5\\)`));
    }
    const v5 = blankReport();
    new DataView(v5.buffer).setUint32(0x00, 5, true);
    expect(parseReport(v5).version).toBe(5);
  });

  it("requires guest policy bit 17 and clear bits 63:26", () => {
    expect(() => parseGuestPolicy(0n)).toThrow(/bit 17 is reserved and must be 1/);
    expect(() => parseGuestPolicy((1n << 17n) | (1n << 26n))).toThrow(/63:26 are reserved/);
    const p = parseGuestPolicy((1n << 17n) | (1n << 19n) | (1n << 16n) | 0x0102n);
    expect(p).toMatchObject({ debug: true, smt: true, migrateMa: false, abiMajor: 1, abiMinor: 2 });
    const r = blankReport();
    new DataView(r.buffer).setBigUint64(0x08, 0n, true);
    expect(() => parseReport(r)).toThrow(/bit 17/);
  });

  it("decodes signer info and rejects reserved values", () => {
    expect(parseSignerInfo(0)).toEqual({ signingKey: 0, maskChipKey: false, authorKeyEn: false });
    expect(parseSignerInfo(0b00111)).toEqual({ signingKey: 1, maskChipKey: true, authorKeyEn: true });
    expect(parseSignerInfo(7 << 2).signingKey).toBe(7);
    expect(() => parseSignerInfo(2 << 2)).toThrow(/reserved, got 2/);
    expect(() => parseSignerInfo(6 << 2)).toThrow(/reserved, got 6/);
    expect(() => parseSignerInfo(1 << 5)).toThrow(/31:5 are reserved/);
    const r = blankReport();
    new DataView(r.buffer).setUint32(0x48, 3 << 2, true);
    expect(() => parseReport(r)).toThrow(/reserved, got 3/);
  });

  it("decodes platform info and rejects reserved bits", () => {
    expect(parsePlatformInfo(0b1000_0101n)).toMatchObject({ smtEnabled: true, eccEnabled: true, tioEnabled: true, tsmeEnabled: false });
    expect(() => parsePlatformInfo(1n << 8n)).toThrow(/unrecognized platform info bit/);
  });

  it("derives the product line from the CPUID family and model", () => {
    expect(fmsOf(cpuid1EaxOf(0x19, 0x11, 1))).toEqual({ family: 0x19, model: 0x11, stepping: 1 });
    expect(cpuid1EaxOf(0x1a, 0x02, 0)).toBe(0x00b00f20);
    const genoa = blankReport();
    expect(productLine(parseReport(genoa))).toBe("Genoa");
    const turin = blankReport();
    turin[0x188] = 0x1a;
    turin[0x189] = 0x02;
    expect(productLine(parseReport(turin))).toBe("Turin");
    const milan = blankReport();
    milan[0x189] = 0x01;
    expect(() => productLine(parseReport(milan))).toThrow(/unsupported SEV product in report CPUID 0xa00f11/);
    const other = blankReport();
    other[0x189] = 0x22;
    expect(() => productLine(parseReport(other))).toThrow(/unsupported SEV product/);
  });

  it("converts the little-endian signature to big-endian r‖s and rejects oversized scalars", () => {
    const r = blankReport();
    r[0x2a0] = 0x01; // r = 1
    r[0x2a0 + 47] = 0x02; // r's most significant byte
    r[0x2e8] = 0x03; // s = 3
    const raw = signatureRaw(parseReport(r));
    expect(raw).toHaveLength(96);
    expect(raw[0]).toBe(0x02);
    expect(raw[47]).toBe(0x01);
    expect(raw[95]).toBe(0x03);
    r[0x2a0 + 48] = 0x01;
    expect(() => signatureRaw(parseReport(r))).toThrow(/exceeds the P-384 scalar size/);
  });

  it("formats the identity as 64 bytes of lowercase hex", () => {
    expect(identity(new Uint8Array(64).fill(0xab))).toBe("ab".repeat(64));
    expect(() => identity(new Uint8Array(63))).toThrow(/must be 64 bytes, got 63/);
  });
});

// ---------------------------------------------------------------- TCB layouts

describe("sev tcb", () => {
  const parts0: TcbParts = { layout: TCB_LAYOUT_0, ucodeSpl: 0xd4, snpSpl: 0x17, spl7: 0, spl6: 0, spl5: 0, spl4: 0, teeSpl: 0, blSpl: 0x0a, fmcSpl: 0 };
  const parts1: TcbParts = { layout: TCB_LAYOUT_1, ucodeSpl: 0xff, snpSpl: 0x11, spl7: 0, spl6: 0, spl5: 0, spl4: 0, teeSpl: 0x22, blSpl: 0x33, fmcSpl: 0x44 };

  it("round-trips both layouts", () => {
    const tcb0 = composeTcb(parts0);
    expect(tcb0).toBe(0xd417000000000000n | 0x0an);
    expect(decomposeTcb(TCB_LAYOUT_0, tcb0)).toEqual(parts0);
    const tcb1 = composeTcb(parts1);
    expect(tcb1).toBe(0xff00000011223344n);
    expect(decomposeTcb(TCB_LAYOUT_1, tcb1)).toEqual(parts1);
  });

  it("rejects reserved bits, oversized levels and misplaced levels", () => {
    expect(() => decomposeTcb(TCB_LAYOUT_1, 1n << 40n)).toThrow(/non-zero reserved bits in Turin TCB/);
    expect(() => composeTcb({ ...parts0, snpSpl: 128 })).toThrow(/SnpSpl TCB part is 128/);
    expect(() => composeTcb({ ...parts1, fmcSpl: 200 })).toThrow(/FmcSpl TCB part is 200/);
    expect(composeTcb({ ...parts0, ucodeSpl: 255 }) >> 56n).toBe(255n);
    expect(() => composeTcb({ ...parts0, fmcSpl: 1 })).toThrow(/FmcSpl is not defined for TCB struct version 0/);
    expect(() => composeTcb({ ...parts1, spl5: 1 })).toThrow(/reserved Turin TCB components must be zero/);
  });

  it("orders levels component-wise within one layout", () => {
    expect(tcbLe(parts0, parts0)).toBe(true);
    expect(tcbLe({ ...parts0, blSpl: 0x09 }, parts0)).toBe(true);
    expect(tcbLe({ ...parts0, blSpl: 0x0b }, parts0)).toBe(false);
    expect(tcbLe({ ...parts0, ucodeSpl: 0, snpSpl: 0x18 }, parts0)).toBe(false);
    expect(tcbLe(parts0, { ...parts1 })).toBe(false);
    expect(formatTcb(parts1)).toBe("{BlSpl:51 TeeSpl:34 SnpSpl:17 UcodeSpl:255 FmcSpl:68}");
  });
});

// ---------------------------------------------------------------- VCEK and roots

describe("sev roots", () => {
  it("parses the embedded Genoa and Turin chains as ASK then ARK", () => {
    const genoa = parseAmdRoots(AMD_GENOA_CERT_CHAIN_PEM);
    expect(genoa.ask.subjectCommonName).toBe("SEV-Genoa");
    expect(genoa.ark.subjectCommonName).toBe("ARK-Genoa");
    const turin = parseAmdRoots(AMD_TURIN_CERT_CHAIN_PEM);
    expect(turin.ask.subjectCommonName).toBe("SEV-Turin");
    expect(turin.ark.subjectCommonName).toBe("ARK-Turin");
    expect(() => parseAmdRoots(AMD_GENOA_CERT_CHAIN_PEM + AMD_TURIN_CERT_CHAIN_PEM)).toThrow(/got 4 blocks/);
  });

  it("checks the document chain's shape without reading its certificates", () => {
    const [ask, ark] = AMD_GENOA_CERT_CHAIN_PEM.split("-----END CERTIFICATE-----\n").map((b) => `${b}-----END CERTIFICATE-----\n`);
    expect(() => checkCertChainShape(`${ask}${ark}`)).not.toThrow();
    expect(() => checkCertChainShape(`${ask}\n\n${ark}\n`)).not.toThrow();
    expect(() => checkCertChainShape(ask)).toThrow(/got 1 blocks/);
    expect(() => checkCertChainShape(`${ask}${ark}${ask}`)).toThrow(/got 3 blocks/);
    expect(() => checkCertChainShape(`${ask}-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n${ark}`)).toThrow(/"PUBLIC KEY" block/);
    expect(() => checkCertChainShape(`${ask}${ark}trailing`)).toThrow(/data outside its certificates/);
    expect(() => checkCertChainShape(`-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n${ark}`)).toThrow(/empty CERTIFICATE block/);
    expect(() => checkCertChainShape(`${ask}-----BEGIN CERTIFICATE-----\nAAAA\n`)).toThrow(/unterminated/);
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("sev vcek"), () => {
  let real: AmdMaterial & { verification_time_unix: number };
  let realReport: Uint8Array;
  let vcek: Certificate;
  beforeAll(() => {
    const fixture = loadFixture("real-frozen/real-sev-inference-tinfoil.json");
    const material = amdMaterial(fixture);
    if (material.verification_time_unix === undefined) throw new Error("real-frozen vector states no verification time");
    real = { ...material, verification_time_unix: material.verification_time_unix };
    realReport = reportOf(fixture);
    vcek = parseCertificate(b64(real.vcek_der_base64));
  });

  it("reads the production VCEK's hardware id and TCB from its private extensions", () => {
    const report = parseReport(realReport);
    const exts = parseVcekExtensions(vcek);
    expect(exts.productName).toBe("Genoa");
    expect(exts.hwid).toEqual(report.chipId);
    expect(exts.tcb).toEqual(decomposeTcb(TCB_LAYOUT_0, report.reportedTcb));
  });

  it("accepts the production VCEK's shape for Genoa and rejects it for Turin", () => {
    expect(checkVcekShape(vcek, "Genoa").hwid).toHaveLength(64);
    expect(() => checkVcekShape(vcek, "Turin")).toThrow(/different TCB formats/);
  });

  it("rejects extensions that are not the KDS ones, a CSP id, and a missing level", () => {
    const extra: Certificate = { ...vcek, extensions: [...vcek.extensions, { oid: "1.2.3.4", critical: false, value: new Uint8Array() }] };
    expect(() => parseVcekExtensions(extra)).toThrow(/1\.2\.3\.4 is not an AMD KDS extension/);
    const csp: Certificate = { ...vcek, extensions: [...vcek.extensions, { oid: "1.3.6.1.4.1.3704.1.5", critical: false, value: new Uint8Array([0x16, 0x01, 0x61]) }] };
    expect(() => parseVcekExtensions(csp)).toThrow(/unexpected CSP_ID/);
    const noBl: Certificate = { ...vcek, extensions: vcek.extensions.filter((e) => e.oid !== "1.3.6.1.4.1.3704.1.3.1") };
    expect(() => parseVcekExtensions(noBl)).toThrow(/no BlSpl extension/);
    const fmc: Certificate = { ...vcek, extensions: [...vcek.extensions, { oid: "1.3.6.1.4.1.3704.1.3.9", critical: false, value: new Uint8Array([0x02, 0x01, 0x00]) }] };
    expect(() => parseVcekExtensions(fmc)).toThrow(/FmcSpl extension is not valid for TCB struct version 0/);
    const bigLevel: Certificate = {
      ...vcek,
      extensions: vcek.extensions.map((e) => (e.oid === "1.3.6.1.4.1.3704.1.3.3" ? { ...e, value: new Uint8Array([0x02, 0x02, 0x01, 0x00]) } : e)),
    };
    expect(() => parseVcekExtensions(bigLevel)).toThrow(/SnpSpl extension value 256 is not a uint8/);
  });

  it("rejects a VCEK whose issuer is not the product's signing key", () => {
    const [ask] = AMD_TURIN_CERT_CHAIN_PEM.split("-----END CERTIFICATE-----\n");
    const turinAsk = parseCertificate(b64(ask.replace("-----BEGIN CERTIFICATE-----", "").replace(/\s+/g, "")));
    const reissued: Certificate = { ...vcek, issuer: turinAsk.subject };
    expect(() => checkVcekShape(reissued, "Genoa")).toThrow(/VCEK issuer common name "SEV-Turin" is not "SEV-Genoa"/);
    const renamed: Certificate = { ...vcek, subject: vcek.issuer };
    expect(() => checkVcekShape(renamed, "Genoa")).toThrow(/VCEK subject common name "SEV-Genoa" is not "SEV-VCEK"/);
  });
});

// ---------------------------------------------------------------- authentication

/** The reason each reject vector fails for; a vector that rejects for another reason leaves its rule untested. */
const SEV_REJECTIONS: Readonly<Record<string, RegExp>> = {
  "s1-report-version": /no CPUID product identity \(report version 2/,
  "s12-signer-key": /not VCEK-signed/,
  "s20-product": /unsupported SEV product/,
  "s26-revoked-ask": /ASK was revoked/,
  "s26-wrong-root": /error verifying VCEK certificate/,
  "s8-s25-signature": /report signature verification error/,
  "struct-bad-chain": /amd-vcek collateral: cert_chain_pem/,
  "struct-crl-expired": /amd-crl collateral is outside its validity window/,
  "struct-crl-not-yet-valid": /amd-crl collateral is outside its validity window/,
  "struct-empty-crl": /amd-crl collateral carries an empty CRL/,
  "struct-empty-vcek": /amd-vcek collateral carries an empty VCEK/,
  "struct-no-crl": /no amd-crl endorsement collateral/,
  "struct-no-vcek": /no amd-vcek endorsement collateral/,
};

describe.skipIf(withoutVectors)(vectorsTitle("authenticateSev"), () => {
  let real: AmdMaterial & { verification_time_unix: number };
  let realReport: Uint8Array;
  let realAt: Date;
  beforeAll(() => {
    const fixture = loadFixture("real-frozen/real-sev-inference-tinfoil.json");
    const material = amdMaterial(fixture);
    if (material.verification_time_unix === undefined) throw new Error("real-frozen vector states no verification time");
    real = { ...material, verification_time_unix: material.verification_time_unix };
    realReport = reportOf(fixture);
    realAt = unix(real.verification_time_unix);
  });

  const evidence = (set: AmdMaterial, report: Uint8Array) => ({
    report,
    vcekDer: b64(set.vcek_der_base64),
    certChainPem: set.cert_chain_pem,
    crlDer: b64(set.crl_der_base64),
  });

  it("authenticates the production report under the embedded Genoa roots at the capture time", async () => {
    const q = await authenticateSev(evidence(real, realReport), realAt);
    const report = parseReport(realReport);
    expect(q.productLine).toBe("Genoa");
    expect(q.identity).toBe(toHex(report.chipId));
    expect(q.measurement).toEqual({ platform: "sev-snp", launch: report.measurement });
    expect(q.vcek.hwid).toEqual(report.chipId);
    expect(q.report.version).toBe(3);
  });

  it("rejects an invalid clock, a stale CRL window and empty collateral", async () => {
    await expect(authenticateSev(evidence(real, realReport), new Date(NaN))).rejects.toThrow(/verification time is required/);
    await expect(authenticateSev(evidence(real, realReport), new Date(0))).rejects.toThrow(/amd-crl collateral is outside its validity window/);
    await expect(authenticateSev({ ...evidence(real, realReport), vcekDer: new Uint8Array() }, realAt)).rejects.toThrow(/empty VCEK/);
    await expect(authenticateSev({ ...evidence(real, realReport), crlDer: new Uint8Array() }, realAt)).rejects.toThrow(/empty CRL/);
    await expect(authenticateSev({ ...evidence(real, realReport), crlDer: new Uint8Array([0x30, 0x00]) }, realAt)).rejects.toThrow(/parsing amd-crl collateral/);
    await expect(authenticateSev({ ...evidence(real, realReport), certChainPem: "" }, realAt)).rejects.toThrow(/amd-vcek collateral: cert_chain_pem/);
  });

  it("rejects a report whose signed bytes or signature were altered", async () => {
    const body = new Uint8Array(realReport);
    body[0x90] ^= 1;
    await expect(authenticateSev(evidence(real, body), realAt)).rejects.toThrow(/report signature verification error/);
    const sig = new Uint8Array(realReport);
    sig[0x2a0] ^= 1;
    await expect(authenticateSev(evidence(real, sig), realAt)).rejects.toThrow(/report signature verification error/);
    const algo = new Uint8Array(realReport);
    new DataView(algo.buffer).setUint32(0x34, 2, true);
    await expect(authenticateSev(evidence(real, algo), realAt)).rejects.toThrow(/unknown SignatureAlgo: 2/);
  });

  it("rejects the Turin roots for a Genoa report, and a VCEK that is not DER", async () => {
    await expect(authenticateSev(evidence(real, realReport), realAt, { dangerousTestOnlyRoot: utf8(AMD_TURIN_CERT_CHAIN_PEM) })).rejects.toThrow(
      /VCEK issuer|error verifying VCEK certificate/,
    );
    await expect(authenticateSev({ ...evidence(real, realReport), vcekDer: new Uint8Array([0x30, 0x00]) }, realAt)).rejects.toThrow(
      /could not interpret VCEK DER bytes/,
    );
    await expect(authenticateSev(evidence(real, realReport), realAt, { dangerousTestOnlyRoot: utf8("not a chain") })).rejects.toThrow(
      /parsing AMD Genoa root certificates/,
    );
  });

  it("rejects a report that is not VCEK-signed before touching the certificate", async () => {
    const r = new Uint8Array(realReport);
    new DataView(r.buffer).setUint32(0x48, 7 << 2, true);
    await expect(authenticateSev(evidence(real, r), realAt)).rejects.toThrow(/not VCEK-signed/);
  });

  describe("quote-sev vectors through quote.authenticate", () => {
    for (const fixture of sevFixtures) {
      const { expected } = fixture;
      it(`${fixture.id}: ${expected.accepted ? "accepts" : "rejects"}`, async () => {
        const doc = await dangerousTestOnlyDecode(inputBytes(fixture, "document_b64"));
        const at = fixture.input.verification_time_unix !== undefined ? unix(fixture.input.verification_time_unix) : new Date();
        const run = authenticate(doc.cpuEvidence(), doc.cpuEndorsements(), at, { dangerousTestOnlyRoots: { amd: rootsOf(fixture) } });
        if (expected.accepted) {
          const auth = await run;
          expect(auth.platform).toBe("sev-snp");
          expect(auth.identity).toBe(toHex(parseReport(reportOf(fixture)).chipId));
          expect(auth.sev?.productLine).toBe("Genoa");
          expect(auth.evidence.report).toEqual(reportOf(fixture));
        } else {
          const reason = SEV_REJECTIONS[fixture.id];
          expect(reason, `no expected reason for vector ${fixture.id}`).toBeDefined();
          await expect(run).rejects.toThrow(reason);
        }
      });
    }
  });

  it("dispatches on the evidence format", async () => {
    const doc = await dangerousTestOnlyDecode(inputBytes(loadFixture("quote-sev/sev-happy.json"), "document_b64"));
    const ev = doc.cpuEvidence();
    await expect(authenticate({ ...ev, format: "https://tinfoil.sh/format/other/v1" }, doc.cpuEndorsements(), realAt)).rejects.toThrow(
      /unsupported cpu_evidence format/,
    );
    // The TDX arm takes its own collateral; without it the SEV report never reaches the TDX parser.
    await expect(authenticate({ ...ev, format: "https://tinfoil.sh/format/tdx-quote/v1" }, {}, realAt)).rejects.toThrow(/no intel-pcs endorsement collateral/);
  });
});

// ---------------------------------------------------------------- expectations

describe.skipIf(withoutVectors)(vectorsTitle("sev expectations"), () => {
  let q: SevQuote;
  let policy: SevSnpPolicy;
  let hostData: Uint8Array;
  beforeAll(async () => {
    const fixture = loadFixture("real-frozen/real-sev-inference-tinfoil.json");
    const material = amdMaterial(fixture);
    const report = reportOf(fixture);
    q = await authenticateSev(
      { report, vcekDer: b64(material.vcek_der_base64), certChainPem: material.cert_chain_pem, crlDer: b64(material.crl_der_base64) },
      unix(material.verification_time_unix!),
    );
    const artifact = parseArtifact(new Uint8Array(readFileSync(new URL("./fixtures/platform-endorsements.json", import.meta.url))));
    const found = policyFor(artifact, q.identity, "sev-snp").policy.sevSnp;
    if (found === undefined) throw new Error("the endorsed policy for the production machine is not an SEV-SNP policy");
    policy = found;
    hostData = decodeHex("host_data", policy.hostData, 32);
  });

  const assemble = (p: SevSnpPolicy = policy, quote: SevQuote = q) => assembleSev(p, quote, quote.report.measurement, quote.report.reportData, hostData);
  const withReport = (changes: Partial<SevQuote["report"]>): SevQuote => ({ ...q, report: { ...q.report, ...changes } });

  it("validates the production report against the policy endorsed for its machine", () => {
    const e = assemble();
    expect(e.productLine).toBe("Genoa");
    expect(e.chipId).toEqual(q.report.chipId);
    expect(() => validateSev(e, q)).not.toThrow();
  });

  it("requires the product's TCB and platform fields", () => {
    expect(() => assemble({ ...policy, minimumTcb: { ...policy.minimumTcb, fmcSpl: 1 } })).toThrow(/fmc_spl is not valid for product line Genoa/);
    expect(() => assemble({ ...policy, platformInfo: { ...policy.platformInfo, iommuWriteSafe: true } })).toThrow(/iommu_write_safe is not valid/);
    const turin: SevQuote = { ...q, productLine: "Turin" };
    expect(() => assemble(policy, turin)).toThrow(/fmc_spl is required for product line Turin/);
    expect(() => assemble({ ...policy, minimumApiVersion: "1" })).toThrow(/minimum_api_version "1" is not maj.min/);
    expect(() => assemble({ ...policy, minimumAbiVersion: "1.256" })).toThrow(/minimum_abi_version minor: value out of range/);
    expect(() => assembleSev(policy, q, q.report.measurement, q.report.reportData, new Uint8Array(31))).toThrow(/HOST_DATA expectation must be 32 bytes/);
    expect(() => assembleSev(policy, q, q.report.measurement, new Uint8Array(63), hostData)).toThrow(/REPORT_DATA expectation must be 64 bytes/);
    expect(() => assemble({ ...policy, requireIdBlock: true })).toThrow(/not supported/);
  });

  it("compares the identity fields verbatim", () => {
    const e = assemble();
    const flip = (b: Uint8Array): Uint8Array => {
      const out = new Uint8Array(b);
      out[0] ^= 1;
      return out;
    };
    expect(() => validateSev({ ...e, reportData: flip(e.reportData) }, q)).toThrow(/REPORT_DATA does not match/);
    expect(() => validateSev({ ...e, hostData: flip(e.hostData) }, q)).toThrow(/HOST_DATA does not match/);
    expect(() => validateSev({ ...e, launch: flip(e.launch) }, q)).toThrow(/MEASUREMENT does not match/);
    expect(() => validateSev({ ...e, chipId: flip(e.chipId) }, q)).toThrow(/CHIP_ID does not match/);
    expect(() => validateSev(e, withReport({ familyId: flip(q.report.familyId) }))).toThrow(/FAMILY_ID does not match/);
    expect(() => validateSev(e, withReport({ imageId: flip(q.report.imageId) }))).toThrow(/IMAGE_ID does not match/);
  });

  it("requires the guest policy and platform info to match exactly and the ABI version to meet the floor", () => {
    const e = assemble();
    const debug = withReport({ policy: q.report.policy ^ (1n << 19n) });
    expect(() => validateSev(e, debug)).toThrow(/guest policy does not match/);
    expect(() => validateSev(assemble({ ...policy, guestPolicy: { ...policy.guestPolicy, debug: !policy.guestPolicy.debug } }), q)).toThrow(
      /guest policy does not match/,
    );
    expect(() => validateSev(assemble({ ...policy, minimumAbiVersion: "255.255" }), q)).toThrow(/required policy ABI version \(255\.255\) is greater/);
    expect(() => validateSev(e, withReport({ platformInfo: q.report.platformInfo ^ 1n }))).toThrow(/PLATFORM_INFO does not match/);
    expect(() => validateSev(e, withReport({ platformInfo: q.report.platformInfo | (1n << 8n) }))).toThrow(/unrecognized platform info bit/);
  });

  it("orders the TCB levels against the certificate and the floors", () => {
    const e = assemble();
    const r = q.report;
    expect(() => validateSev(e, withReport({ reportedTcb: r.reportedTcb + 1n }))).toThrow(/REPORTED_TCB .* does not match the TCB of the VCEK certificate/);
    expect(() => validateSev(e, withReport({ currentTcb: r.currentTcb - 1n, committedTcb: r.committedTcb - 1n }))).toThrow(
      /CURRENT_TCB .* is lower than the TCB of the VCEK certificate/,
    );
    expect(() => validateSev(e, withReport({ committedTcb: r.committedTcb - 1n }))).toThrow(/COMMITTED_TCB .* does not match the report's CURRENT_TCB/);
    const provisional = assemble({ ...policy, permitProvisionalFirmware: true });
    expect(() => validateSev(provisional, withReport({ committedTcb: r.committedTcb - 1n }))).not.toThrow();
    expect(() => validateSev(provisional, withReport({ committedTcb: r.committedTcb + 1n }))).toThrow(/COMMITTED_TCB/);
    // The committed level must meet the floor even when provisional firmware is permitted.
    const reported = decomposeTcb(TCB_LAYOUT_0, r.reportedTcb);
    const atReported = assemble({
      ...policy,
      permitProvisionalFirmware: true,
      minimumTcb: { blSpl: reported.blSpl, teeSpl: reported.teeSpl, snpSpl: reported.snpSpl, ucodeSpl: reported.ucodeSpl },
    });
    expect(() => validateSev(atReported, q)).not.toThrow();
    expect(() => validateSev(atReported, withReport({ committedTcb: r.committedTcb - 1n }))).toThrow(
      /COMMITTED_TCB .* is lower than the policy minimum TCB/,
    );
    const floor = { ...policy.minimumTcb, ucodeSpl: 255 };
    expect(() => validateSev(assemble({ ...policy, minimumTcb: floor }), q)).toThrow(/REPORTED_TCB .* is lower than the policy minimum TCB/);
    expect(() => validateSev(assemble({ ...policy, minimumLaunchTcb: floor }), q)).toThrow(/LAUNCH_TCB .* is lower than the policy minimum launch TCB/);
    expect(() => validateSev(e, withReport({ launchTcb: 1n << 40n, currentTcb: r.currentTcb }))).toThrow(/LAUNCH_TCB/);
  });

  it("enforces the firmware build and version floors and committed firmware", () => {
    const e = assemble();
    const r = q.report;
    expect(() => validateSev(assemble({ ...policy, minimumBuild: r.currentBuild + 1 }), q)).toThrow(/build number .* is less than the required minimum/);
    expect(() => validateSev(assemble({ ...policy, minimumApiVersion: "255.0" }), q)).toThrow(/API version .* is less than the required minimum \(255\.0\)/);
    expect(() => validateSev(e, withReport({ committedBuild: r.currentBuild + 1 }))).toThrow(/committed build number .* does not match/);
    expect(() => validateSev(e, withReport({ committedMinor: r.currentMinor + 1 }))).toThrow(/committed API version .* does not match/);
    const provisional = assemble({ ...policy, permitProvisionalFirmware: true });
    expect(() => validateSev(provisional, withReport({ committedBuild: r.currentBuild + 1 }))).toThrow(/is greater than the current build number/);
    // Provisional firmware does not lift the floors off the committed firmware.
    const buildFloor = assemble({ ...policy, permitProvisionalFirmware: true, minimumBuild: r.currentBuild });
    expect(() => validateSev(buildFloor, withReport({ committedBuild: r.currentBuild - 1 }))).toThrow(/committed build number .* is less than the required minimum/);
    const versionFloor = assemble({ ...policy, permitProvisionalFirmware: true, minimumApiVersion: `${r.currentMajor}.${r.currentMinor}` });
    expect(() => validateSev(versionFloor, withReport({ committedMinor: r.currentMinor - 1 }))).toThrow(/committed API version .* is less than the required minimum/);
    expect(() => validateSev(assemble({ ...policy, minimumGuestSvn: r.guestSvn + 1 }), q)).toThrow(/GUEST_SVN .* is less than the required minimum/);
    expect(() => validateSev(assemble({ ...policy, vmpl: 3n }), withReport({ vmpl: 2 }))).toThrow(/report VMPL 2 is not 3/);
  });

  it("requires the mitigation vectors to cover the floors", () => {
    const r = q.report;
    const launchFloor = assemble({ ...policy, minimumLaunchMitigationVector: r.launchMitVector | (1n << 63n) });
    expect(() => validateSev(launchFloor, q)).toThrow(/launch mitigation vector .* is missing required bits/);
    expect(() => validateSev(launchFloor, withReport({ launchMitVector: r.launchMitVector | (1n << 63n) }))).not.toThrow();
    const currentFloor = assemble({ ...policy, minimumCurrentMitigationVector: r.currentMitVector | (1n << 62n) });
    expect(() => validateSev(currentFloor, q)).toThrow(/current mitigation vector .* is missing required bits/);
    expect(() => validateSev(currentFloor, withReport({ currentMitVector: r.currentMitVector | (1n << 62n) }))).not.toThrow();
  });

  it("binds the report to the VCEK's hardware id and rejects ID-block launches", () => {
    const e = assemble();
    const otherHwid = new Uint8Array(q.vcek.hwid);
    otherHwid[0] ^= 1;
    expect(() => validateSev(e, { ...q, vcek: { ...q.vcek, hwid: otherHwid } })).toThrow(/CHIP_ID is not the same as the VCEK certificate's HWID/);
    expect(() => validateSev(e, { ...q, vcek: { ...q.vcek, hwid: otherHwid.subarray(0, 7) } })).toThrow(/HWID has unsupported size 7/);
    expect(() => validateSev(e, { ...q, vcek: { ...q.vcek, hwid: q.vcek.hwid.subarray(0, 8) } })).not.toThrow();
    const zeroId = new Uint8Array(64);
    expect(() => validateSev({ ...e, chipId: zeroId }, withReport({ chipId: zeroId }))).toThrow(/CHIP_ID is all zero/);
    const signer = (bits: number) => withReport({ signer: parseSignerInfo(bits) });
    expect(() => validateSev(e, signer(1))).toThrow(/author key; ID-block launches are unsupported/);
    expect(() => validateSev(e, signer(2))).toThrow(/masks CHIP_ID/);
    const idKey = new Uint8Array(48);
    idKey[47] = 1;
    expect(() => validateSev(e, withReport({ idKeyDigest: idKey }))).toThrow(/carries an ID block/);
    expect(() => validateSev(e, withReport({ authorKeyDigest: idKey }))).toThrow(/carries an author key digest/);
  });
});
