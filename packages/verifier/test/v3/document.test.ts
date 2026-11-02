/**
 * Port of tinfoil-go verify/document/{document,collateral,collateral_accessors,
 * config,attested_keys}_test.go. Test titles are the Go test (and subtest)
 * names. builder_test.go's Build-specific assertions are not ported; the
 * builder in helpers/builder.ts only makes fixtures.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  AMD_CRL_V1_FORMAT,
  AMD_VCEK_V1_FORMAT,
  CONFIG_ENDORSEMENT_V1_FORMAT,
  CONFIG_ID,
  decode as decodeCollateralSet,
  decodeEntries,
  FORMAT_V2,
  FORMAT_V3,
  FRESHNESS_ID_CODE,
  FRESHNESS_ID_PLATFORM,
  INTEL_PCS_V1_FORMAT,
  NotFoundError,
  ROLE_ENDORSEMENT,
  ROLE_REFERENCE_VALUES,
  SIGSTORE_CODE_V1_FORMAT,
  SIGSTORE_FRESHNESS_V1_FORMAT,
  SIGSTORE_PLATFORM_V1_FORMAT,
  SUBJECT_CPU,
  type CollateralSet,
} from "../../src/v3/document/collateral/collateral.js";
import {
  computeReportData,
  CRYPTO_MATERIAL_ID_HPKE,
  CRYPTO_MATERIAL_ID_TLS,
  dangerousTestOnlyDecode,
  Document,
  InvalidInputError,
  KEY_SPKI_FP_SHA256_V1_FORMAT,
  KEY_SPKI_V1_FORMAT,
  KEY_X25519_HPKE_V1_FORMAT,
  NONCE_SIZE,
  parse,
  REPORT_DATA_V1_ALGORITHM,
  SEV_SNP_REPORT_V1_FORMAT,
  TDX_QUOTE_V1_FORMAT,
  type CryptoMaterialItem,
  type DecodedDocument,
} from "../../src/v3/document/document.js";
import type { JsonObject } from "../../src/v3/internal/json/index.js";
import { strictParse } from "../../src/v3/internal/json/index.js";
import {
  b64,
  build,
  buildDocument,
  fakeQuote,
  marshalDocument,
  marshalEntries,
  type RawDocument,
  type WireEntry,
} from "./helpers/builder.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => new TextDecoder().decode(b);
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const repeat = (byte: number, n: number): Uint8Array => new Uint8Array(n).fill(byte);
const sha = (b: Uint8Array | string): Uint8Array => new Uint8Array(createHash("sha256").update(b).digest());

function testNonce(): Uint8Array {
  return Uint8Array.from({ length: NONCE_SIZE }, (_, i) => i);
}

/**
 * Go buildTestDocument: a well-formed document around a dummy 1184-byte SEV
 * report, with tls and hpke keys, no devices, and one vcek entry.
 */
async function buildTestDocument(nonce: Uint8Array): Promise<{ raw: RawDocument; bytes: Uint8Array }> {
  return buildDocument(
    {
      nonce,
      cryptoMaterial: [
        { id: CRYPTO_MATERIAL_ID_TLS, format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: hex(repeat(0xaa, 32)) },
        { id: CRYPTO_MATERIAL_ID_HPKE, format: KEY_X25519_HPKE_V1_FORMAT, data: hex(repeat(0xbb, 32)) },
      ],
      deviceEvidence: [],
      collateral: [
        {
          id: "cpu-endorsement",
          role: ROLE_ENDORSEMENT,
          format: AMD_VCEK_V1_FORMAT,
          subjects: [SUBJECT_CPU],
          data: `{"vcek_der_base64":"","cert_chain_pem":""}`,
        },
      ],
    },
    fakeQuote(SEV_SNP_REPORT_V1_FORMAT, repeat(0x01, 1184)),
  );
}

/** Decodes a wire collateral array as parse does (strict JSON, then collateral.Decode). */
function decodeWire(entries: WireEntry[]): CollateralSet {
  return decodeCollateralSet(decodeEntries(strictParse(enc(marshalEntries(entries)))));
}

/** A Document from decoded fields, as Go tests build &Document{...} directly. Unbound: no REPORT_DATA. */
function docWith(fields: Partial<DecodedDocument>): Document {
  return new Document({
    challenge: { nonce: "", reportData: "" },
    cpuEvidence: { format: "", report: new Uint8Array() },
    endorsedHashes: { cryptoMaterial: "", deviceEvidence: "" },
    cryptoMaterialRaw: new Uint8Array(),
    deviceEvidenceRaw: new Uint8Array(),
    cryptoMaterial: [],
    deviceEvidence: [],
    collateralFormat: "",
    collateral: decodeCollateralSet([]),
    ...fields,
  });
}

/** Go documentWithCollateral: decodes entries as parse does, for CPU evidence of the given format. */
function documentWithCollateral(evidenceFormat: string, entries: WireEntry[]): Document {
  return docWith({ cpuEvidence: { format: evidenceFormat, report: new Uint8Array() }, collateral: decodeWire(entries) });
}

/**
 * Go mutateSection: decodes the endorsed section field, applies mutate to its
 * text, re-encodes it without updating the endorsed hashes.
 */
function mutateSection(docBytes: Uint8Array, field: string, mutate: (section: string) => string): Uint8Array {
  const loose = JSON.parse(dec(docBytes)) as Record<string, unknown>;
  const section = Buffer.from(loose[field] as string, "base64").toString("utf8");
  loose[field] = Buffer.from(mutate(section), "utf8").toString("base64");
  return enc(JSON.stringify(loose));
}

const mutateCryptoSection = (docBytes: Uint8Array, mutate: (section: string) => string): Uint8Array =>
  mutateSection(docBytes, "crypto_material", mutate);

function setTopLevel(docBytes: Uint8Array, mutate: (loose: Record<string, unknown>) => void): Uint8Array {
  const loose = JSON.parse(dec(docBytes)) as Record<string, unknown>;
  mutate(loose);
  return enc(JSON.stringify(loose));
}

/** Replaces the first occurrence, as bytes.Replace(..., 1). */
function replaceOnce(docBytes: Uint8Array, from: string, to: string): Uint8Array {
  const s = dec(docBytes);
  expect(s.includes(from)).toBe(true);
  return enc(s.replace(from, () => to));
}

function thrown(f: () => unknown): Error {
  try {
    f();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected an error");
}

const bundleMember = (v: unknown, key: string): unknown => (v as JsonObject).get(key);

// ---------------------------------------------------------------- document_test.go

describe("document_test.go", () => {
  it("TestBuildAndVerify", async () => {
    const nonce = testNonce();
    const { raw: built, bytes } = await buildTestDocument(nonce);

    const doc = await parse(bytes, nonce);
    const reportData = doc.expectedReportData();
    expect(reportData).toBeDefined();
    expect(hex(reportData!)).toBe(built.challenge.report_data);

    const items = doc.cryptoMaterialItems();
    expect(items).toHaveLength(2);
    expect(items[0]!.id).toBe(CRYPTO_MATERIAL_ID_TLS);
    const tls = doc.cryptoMaterialItem(CRYPTO_MATERIAL_ID_TLS);
    expect(tls).toBeDefined();
    expect(tls!.format).toBe(KEY_SPKI_FP_SHA256_V1_FORMAT);
    const original = { ...tls! };
    (items[0] as { data: string }).data = "changed";
    (tls as { data: string }).data = "changed again";
    expect(doc.cryptoMaterialItems()[0]).toEqual(original);
    expect(doc.cryptoMaterialItem(CRYPTO_MATERIAL_ID_TLS)).toEqual(original);

    expect(doc.deviceEvidenceItems()).toEqual([]);
  });

  it("TestExpectedReportDataRequiresParse", async () => {
    // Go checks a nil and a zero-value Document; TS has neither, so check an
    // unbound decode and a Document built from fields.
    const { bytes } = await buildTestDocument(testNonce());
    for (const doc of [await dangerousTestOnlyDecode(bytes), docWith({})]) {
      expect(doc.expectedReportData()).toBeUndefined();
    }
  });

  // CpuEvidence is a plain interface in TS with no Clone method; copying is
  // covered by TestCPUEvidenceReturnsCopies.
  it.skip("TestCPUEvidenceClone (no CPUEvidence.Clone in TS)", () => {});

  it("TestCPUEvidenceReturnsCopies", () => {
    const doc = docWith({ cpuEvidence: { format: SEV_SNP_REPORT_V1_FORMAT, report: enc("report") } });
    const evidence = doc.cpuEvidence();
    evidence.report[0] = "!".charCodeAt(0);
    expect(doc.cpuEvidence().report).toEqual(enc("report"));
  });

  it("TestDeviceEvidenceItemsReturnsCopies", () => {
    const evidence = strictParse(enc(`{"nonce":"original"}`));
    const doc = docWith({ deviceEvidence: [{ id: "gpu", kind: "", vendor: "", format: "", evidence }] });
    const items = doc.deviceEvidenceItems();
    (items[0] as { id: string }).id = "changed";
    // Go also mutates the evidence bytes. TS shares the parsed evidence as a
    // ReadonlyMap by design (see Document's doc comment), so that half is not
    // expressible without casting away readonly.
    const again = doc.deviceEvidenceItems();
    expect(again[0]!.id).toBe("gpu");
    expect(bundleMember(again[0]!.evidence, "nonce")).toBe("original");
  });

  it("TestVerifyNonceMismatch", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const other = testNonce();
    other[0]! ^= 0xff;
    await expect(parse(bytes, other)).rejects.toThrow("challenge nonce does not match the expected nonce");
  });

  it("TestParseRejectsWrongNonceLength", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const longer = new Uint8Array(NONCE_SIZE + 1);
    longer.set(nonce);
    for (const n of [new Uint8Array(0), nonce.slice(0, NONCE_SIZE - 1), longer]) {
      await expect(parse(bytes, n)).rejects.toBeInstanceOf(InvalidInputError);
    }
  });

  it("TestVerifyTamperedDeviceEvidence", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const tampered = mutateSection(bytes, "device_evidence", (s) => s.replace(`{"format"`, `{ "format"`));
    expect(tampered).not.toEqual(bytes);
    await expect(parse(tampered, nonce)).rejects.toThrow("device_evidence hash does not match");
  });

  it("TestVerifyReportDataMismatch", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const tampered = setTopLevel(bytes, (loose) => {
      (loose.challenge as Record<string, string>).report_data = hex(repeat(0x11, 64));
    });
    await expect(parse(tampered, nonce)).rejects.toThrow("challenge report_data does not match the recomputed value");
  });

  it("TestVerifyTransportedBytes", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const tampered = mutateCryptoSection(bytes, (s) => s.replace(`{"format"`, `{ "format"`));
    expect(tampered).not.toEqual(bytes);
    await expect(parse(tampered, nonce)).rejects.toThrow("crypto_material hash");
  });

  it("TestVerifyTamperedKey", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const tampered = mutateCryptoSection(bytes, (s) => s.replace(hex(repeat(0xaa, 32)), hex(repeat(0xac, 32))));
    expect(tampered).not.toEqual(bytes);
    await expect(parse(tampered, nonce)).rejects.toThrow("crypto_material hash");
  });

  it("TestVerifyRejectsUnknownTopLevelMembers", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const tampered = setTopLevel(bytes, (loose) => {
      loose.generated_at = "2026-01-01T00:00:00Z";
    });
    await expect(parse(tampered, nonce)).rejects.toThrow();
  });

  it("TestVerifyRejectsUnknownAlgorithm", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const tampered = replaceOnce(bytes, REPORT_DATA_V1_ALGORITHM, "https://tinfoil.sh/report-data/v2");
    await expect(parse(tampered, nonce)).rejects.toThrow("report_data_algorithm");
  });

  it("TestParseRejectsDuplicateItemIDs", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const filler = hex(repeat(0xcc, 32));
    const dup = mutateCryptoSection(bytes, (s) =>
      s.replace(
        `"items":[{"id":"tls"`,
        `"items":[{"id":"tls","format":"${KEY_SPKI_FP_SHA256_V1_FORMAT}","data":"${filler}"},{"id":"tls"`,
      ),
    );
    expect(dup).not.toEqual(bytes);
    await expect(parse(dup, nonce)).rejects.toThrow(`duplicate crypto_material item id "tls"`);
  });

  it("TestParseRejectsMalformedKeyMaterial", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const short = mutateCryptoSection(bytes, (s) => s.replace(hex(repeat(0xaa, 32)), hex(repeat(0xaa, 8))));
    expect(short).not.toEqual(bytes);
    await expect(parse(short, nonce)).rejects.toThrow("must be 32 bytes");
  });

  it("TestParseRejectsUppercaseHex", async () => {
    const nonce = testNonce();
    const { raw: built, bytes } = await buildTestDocument(nonce);
    const upper = replaceOnce(bytes, built.challenge.nonce, built.challenge.nonce.toUpperCase());
    await expect(parse(upper, nonce)).rejects.toThrow("lowercase hex");
  });

  it("TestParseRejectsNonCanonicalBase64", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const tampered = setTopLevel(bytes, (loose) => {
      const encoded = loose.crypto_material as string;
      loose.crypto_material = encoded.slice(0, 8) + "\n" + encoded.slice(8);
    });
    await expect(parse(tampered, nonce)).rejects.toThrow("crypto_material is not canonical base64");
  });

  describe("TestParseRejectsNonCanonicalReportBase64", async () => {
    const nonce = testNonce();
    const { raw: built, bytes } = await buildTestDocument(nonce);
    const encoded = built.cpu_evidence.report_base64;
    it("fixture ends in AQE=", () => {
      expect(encoded.endsWith("AQE=")).toBe(true);
    });
    it.each([
      ["embedded newline", encoded.slice(0, 8) + "\n" + encoded.slice(8)],
      ["trailing CRLF", encoded + "\r\n"],
      ["nonzero padding bits", encoded.slice(0, -4) + "AQF="],
    ])("%s", async (_name, variant) => {
      const tampered = replaceOnce(bytes, JSON.stringify(encoded), JSON.stringify(variant));
      expect(tampered).not.toEqual(bytes);
      await expect(parse(tampered, nonce)).rejects.toThrow("cpu_evidence.report_base64");
    });
  });

  it("TestParseRejectsOddLengthUnknownFormatData", async () => {
    const nonce = testNonce();
    const { bytes } = await buildTestDocument(nonce);
    const insert = (item: string) => mutateCryptoSection(bytes, (s) => s.replace(`"items":[`, `"items":[${item},`));

    await expect(
      parse(insert(`{"id":"x","format":"https://example.com/key/v9","data":"abc"}`), nonce),
    ).rejects.toThrow(`crypto_material item "x" data is not lowercase hex`);
    await expect(parse(insert(`{"id":"x","format":"https://example.com/key/v9","data":""}`), nonce)).rejects.toThrow(
      `crypto_material item "x" data is empty`,
    );
  });

  it("TestParseRejectsDuplicateCollateralIDs", async () => {
    const nonce = testNonce();
    const { raw } = await buildTestDocument(nonce);
    raw.collateral.push({
      id: raw.collateral[0]!.id,
      role: ROLE_REFERENCE_VALUES,
      format: SIGSTORE_CODE_V1_FORMAT,
      data: `{}`,
    });
    await expect(parse(marshalDocument(raw), nonce)).rejects.toThrow(`duplicate collateral entry id "cpu-endorsement"`);
  });

  it("TestFreshnessSelectsArtifactID", () => {
    const doc = documentWithCollateral("", [
      {
        id: FRESHNESS_ID_CODE,
        role: ROLE_REFERENCE_VALUES,
        format: SIGSTORE_FRESHNESS_V1_FORMAT,
        data: `{"sigstore_bundle":{"mediaType":"code"}}`,
      },
      {
        id: FRESHNESS_ID_PLATFORM,
        role: ROLE_REFERENCE_VALUES,
        format: SIGSTORE_FRESHNESS_V1_FORMAT,
        data: `{"sigstore_bundle":{"mediaType":"platform"}}`,
      },
    ]);

    expect(bundleMember(doc.freshness(FRESHNESS_ID_CODE).bundle, "mediaType")).toBe("code");
    expect(bundleMember(doc.freshness(FRESHNESS_ID_PLATFORM).bundle, "mediaType")).toBe("platform");
    for (const id of ["", "missing-freshness"]) {
      expect(() => doc.freshness(id)).toThrow(NotFoundError);
    }
  });

  it("TestSigstoreReferences", () => {
    const entry = (format: string, repo: string): WireEntry => ({
      id: format,
      role: ROLE_REFERENCE_VALUES,
      format,
      data: `{"repo":"${repo}","tag":"v1","digest":"${"ab".repeat(32)}","sigstore_bundle":{"mediaType":"${repo}"}}`,
    });
    const doc = documentWithCollateral("", [
      entry(SIGSTORE_CODE_V1_FORMAT, "org/code"),
      entry(SIGSTORE_PLATFORM_V1_FORMAT, "org/platform"),
    ]);

    const code = doc.sigstoreCode();
    expect(code.repo).toBe("org/code");
    expect(code.tag).toBe("v1");
    expect(code.digest).toBe("ab".repeat(32));
    expect(bundleMember(code.bundle, "mediaType")).toBe("org/code");

    expect(doc.sigstorePlatform().repo).toBe("org/platform");

    expect(() => docWith({}).sigstoreCode()).toThrow(NotFoundError);
    expect(() => docWith({}).sigstorePlatform()).toThrow(NotFoundError);

    const malformed = { ...entry(SIGSTORE_CODE_V1_FORMAT, "org/code"), data: `{"repo":"org/code","unknown":1}` };
    const err = thrown(() => decodeWire([malformed]));
    expect(err.message).toContain(`parsing ${SIGSTORE_CODE_V1_FORMAT} collateral entry`);
    expect(err).not.toBeInstanceOf(NotFoundError);
  });

  it("TestParseRejectsDuplicateFreshnessArtifactID", async () => {
    const nonce = testNonce();
    const { raw } = await buildTestDocument(nonce);
    const entry: WireEntry = {
      id: FRESHNESS_ID_CODE,
      role: ROLE_REFERENCE_VALUES,
      format: SIGSTORE_FRESHNESS_V1_FORMAT,
      data: `{"sigstore_bundle":{}}`,
    };
    raw.collateral.push(entry, entry);
    await expect(parse(marshalDocument(raw), nonce)).rejects.toThrow(
      `duplicate collateral entry id "${FRESHNESS_ID_CODE}"`,
    );
  });

  it("TestComputeReportData", async () => {
    const nonce = testNonce();
    const cmHash = sha("crypto");
    const deHash = sha("device");

    const got = await computeReportData(nonce, cmHash, deHash);
    const want = new Uint8Array(64);
    want.set(
      createHash("sha256").update(REPORT_DATA_V1_ALGORITHM).update(nonce).update(cmHash).update(deHash).digest(),
    );
    expect(got).toEqual(want);
    expect(got.slice(32)).toEqual(new Uint8Array(32));

    await expect(computeReportData(nonce.slice(0, 16), cmHash, deHash)).rejects.toThrow();
  });

  it("TestDocumentRoundTripPreservesEndorsedBytes", async () => {
    const nonce = testNonce();
    const { raw: built, bytes } = await buildTestDocument(nonce);
    const loose = JSON.parse(dec(bytes)) as Record<string, string>;
    const section = (field: string) => new Uint8Array(Buffer.from(loose[field]!, "base64"));
    expect(hex(sha(section("crypto_material")))).toBe(built.cpu_evidence.endorsed.crypto_material_hash);
    expect(hex(sha(section("device_evidence")))).toBe(built.cpu_evidence.endorsed.device_evidence_hash);
  });
});

// ---------------------------------------------------------------- collateral_test.go

describe("collateral_test.go", () => {
  describe("TestCollateralFormatRoundTrip", () => {
    it.each(["", FORMAT_V2, FORMAT_V3])("%j", async (format) => {
      const nonce = testNonce();
      const data = await build(
        { nonce, collateralFormat: format },
        fakeQuote(SEV_SNP_REPORT_V1_FORMAT, enc("quote")),
      );
      const doc = await parse(data, nonce);
      if (format === FORMAT_V3) {
        expect(doc.collateralFormat()).toBe(format);
      } else {
        expect(doc.collateralFormat()).toBe(FORMAT_V2);
        expect(dec(data)).not.toContain("collateral_format");
      }
    });
  });

  describe("TestRejectsIncompatibleCollateralFormat", () => {
    const legacy: WireEntry = {
      id: "code",
      role: ROLE_REFERENCE_VALUES,
      format: SIGSTORE_CODE_V1_FORMAT,
      data: `{"digest":"digest","sigstore_bundle":{}}`,
    };
    const config: WireEntry = {
      id: CONFIG_ID,
      role: ROLE_REFERENCE_VALUES,
      format: CONFIG_ENDORSEMENT_V1_FORMAT,
      data: `{"endorsement_ref":"sha256:${"a".repeat(64)}","config_base64":"eA==","sigstore_bundle":{}}`,
    };
    it.each<{ name: string; format: string; entries: WireEntry[]; want: string }>([
      { name: "unknown", format: "unknown", entries: [], want: "unsupported collateral format" },
      { name: "legacy code in v3", format: FORMAT_V3, entries: [legacy], want: "legacy code collateral" },
      { name: "config without version", format: "", entries: [config], want: "config and runtime collateral require" },
      { name: "config in v2", format: FORMAT_V2, entries: [config], want: "config and runtime collateral require" },
    ])("$name", async ({ format, entries, want }) => {
      const nonce = testNonce();
      await expect(
        build({ nonce, collateralFormat: format, collateral: entries }, () => {
          throw new Error("invalid collateral must be rejected before requesting a quote");
        }),
      ).rejects.toThrow(want);

      const { raw } = await buildDocument({ nonce }, fakeQuote(SEV_SNP_REPORT_V1_FORMAT, enc("quote")));
      raw.collateral_format = format;
      raw.collateral = entries;
      await expect(parse(marshalDocument(raw), nonce)).rejects.toThrow(want);
    });
  });
});

// ---------------------------------------------------------------- collateral_accessors_test.go

const cpuEntry = (id: string, format: string, data: string): WireEntry => ({
  id,
  role: ROLE_ENDORSEMENT,
  format,
  subjects: [SUBJECT_CPU],
  data,
});

/** Both platforms' CPU collateral. */
const allPlatformEntries = (): WireEntry[] => [
  cpuEntry("vcek", AMD_VCEK_V1_FORMAT, `{"vcek_der_base64":"${b64("vcek der")}","cert_chain_pem":"chain"}`),
  cpuEntry("crl", AMD_CRL_V1_FORMAT, `{"crl_der_base64":"${b64("crl der")}"}`),
  cpuEntry(
    "pcs",
    INTEL_PCS_V1_FORMAT,
    `{"responses":[{"url":"https://pcs.example","headers":{},"body_base64":"${b64("body")}"}]}`,
  ),
];

describe("collateral_accessors_test.go", () => {
  it("TestCPUEndorsementsSelectsEvidencePlatform", () => {
    const sev = documentWithCollateral(SEV_SNP_REPORT_V1_FORMAT, allPlatformEntries()).cpuEndorsements();
    expect(sev).toEqual({
      amdVcek: { vcekDer: enc("vcek der"), certChainPem: "chain" },
      amdCrl: { crlDer: enc("crl der") },
    });

    const tdx = documentWithCollateral(TDX_QUOTE_V1_FORMAT, allPlatformEntries()).cpuEndorsements();
    expect(tdx).toEqual({
      intelPcs: { responses: [{ url: "https://pcs.example", headers: new Map(), body: enc("body") }] },
    });

    const unknown = documentWithCollateral("https://example.com/format/unknown", allPlatformEntries()).cpuEndorsements();
    expect(unknown).toEqual({});
  });

  it("TestCPUEndorsementsLeavesMissingCollateralNil", () => {
    for (const format of [SEV_SNP_REPORT_V1_FORMAT, TDX_QUOTE_V1_FORMAT]) {
      const en = documentWithCollateral(format, []).cpuEndorsements();
      expect(en.amdVcek).toBeUndefined();
      expect(en.amdCrl).toBeUndefined();
      expect(en.intelPcs).toBeUndefined();
    }
  });

  it("TestCPUEndorsementsReturnsCopies", () => {
    const doc = documentWithCollateral(SEV_SNP_REPORT_V1_FORMAT, allPlatformEntries());
    const en = doc.cpuEndorsements();
    en.amdVcek!.vcekDer[0] = "!".charCodeAt(0);
    (en as { amdCrl?: unknown }).amdCrl = undefined;
    const again = doc.cpuEndorsements();
    expect(again.amdVcek!.vcekDer).toEqual(enc("vcek der"));
    expect(again.amdCrl).toBeDefined();
  });

  it("TestReferenceValuesReturnCopies", () => {
    // Go mutates the returned bundle bytes. TS bundles are parsed, ReadonlyMap
    // JSON values shared by design, so the port checks the returned struct is
    // a fresh copy and the bundles decode as sent.
    const doc = documentWithCollateral("", [
      {
        id: "code",
        role: ROLE_REFERENCE_VALUES,
        format: SIGSTORE_CODE_V1_FORMAT,
        data: `{"repo":"o/r","tag":"v1","digest":"ab","sigstore_bundle":{"a":1}}`,
      },
      {
        id: FRESHNESS_ID_CODE,
        role: ROLE_REFERENCE_VALUES,
        format: SIGSTORE_FRESHNESS_V1_FORMAT,
        data: `{"sigstore_bundle":{"b":2}}`,
      },
    ]);
    const code = doc.sigstoreCode();
    (code as { repo: string }).repo = "changed";
    const witness = doc.freshness(FRESHNESS_ID_CODE);
    (witness as { format: string }).format = "changed";

    const codeAgain = doc.sigstoreCode();
    expect(codeAgain.repo).toBe("o/r");
    expect((bundleMember(codeAgain.bundle, "a") as { raw: string }).raw).toBe("1");
    const witnessAgain = doc.freshness(FRESHNESS_ID_CODE);
    expect(witnessAgain.format).toBe(SIGSTORE_FRESHNESS_V1_FORMAT);
    expect((bundleMember(witnessAgain.bundle, "b") as { raw: string }).raw).toBe("2");
  });
});

// ---------------------------------------------------------------- config_test.go

describe("config_test.go", () => {
  it("TestConfigCollateralAccessorsReturnCopies", () => {
    const bundle = strictParse(enc(`{}`));
    const doc = docWith({
      collateral: {
        ...decodeCollateralSet([]),
        config: { reference: "ref", config: enc("config"), bundle },
        runtime: { repo: "", tag: "", digest: "", manifest: enc("manifest"), bundle },
      },
    });
    const config = doc.configEndorsement();
    (config as { reference: string }).reference = "changed";
    config.config[0] = "!".charCodeAt(0);
    const againConfig = doc.configEndorsement();
    expect(againConfig.reference).toBe("ref");
    expect(dec(againConfig.config)).toBe("config");
    expect(againConfig.bundle).toEqual(new Map());

    const runtime = doc.runtime();
    runtime.manifest[0] = "!".charCodeAt(0);
    const againRuntime = doc.runtime();
    expect(dec(againRuntime.manifest)).toBe("manifest");
    expect(againRuntime.bundle).toEqual(new Map());

    const empty = docWith({});
    expect(() => empty.configEndorsement()).toThrow(NotFoundError);
    expect(() => empty.runtime()).toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------- attested_keys_test.go

interface Vector {
  algorithm: string;
  item: CryptoMaterialItem;
  nonce: string;
  crypto_material: string;
  device_evidence: string;
  crypto_material_hash: string;
  device_evidence_hash: string;
  report_data: string;
}

// Public-only vectors shared with sdk-flywheel/v3/attested-keys-vectors.json
// (copied from tinfoil-go verify/document/testdata). Parse must accept and
// preserve key formats the SDK does not interpret.
describe("TestAttestedKeyEnvelopeVectors", () => {
  const vectors = JSON.parse(
    readFileSync(new URL("./fixtures/attested-keys-vectors.json", import.meta.url), "utf8"),
  ) as Vector[];
  it("has three vectors", () => {
    expect(vectors).toHaveLength(3);
  });
  it.each(vectors.map((v) => [v.algorithm, v] as const))("%s", async (_name, v) => {
    const nonce = new Uint8Array(Buffer.from(v.nonce, "hex"));
    const { raw } = await buildTestDocument(nonce);
    raw.crypto_material = v.crypto_material;
    raw.device_evidence = v.device_evidence;
    raw.cpu_evidence.endorsed = {
      crypto_material_hash: v.crypto_material_hash,
      device_evidence_hash: v.device_evidence_hash,
    };
    raw.challenge.report_data = v.report_data;
    const parsed = await parse(marshalDocument(raw), nonce);
    expect(v.item.format).toBe(KEY_SPKI_V1_FORMAT);
    expect(parsed.cryptoMaterialItems()).toEqual([v.item]);
  });
});

describe("review regressions", () => {
  it("binds the nonce as it was when parse was called", async () => {
    const nonce = repeat(0x07, 32);
    const { bytes } = await buildTestDocument(nonce);
    const callerBuffer = nonce.slice();
    const pending = parse(bytes, callerBuffer);
    callerBuffer.fill(0); // mutate after the call, while bind is awaiting hashes
    const doc = await pending;
    const want = await computeReportData(
      nonce,
      new Uint8Array(createHash("sha256").update(sectionBytes(bytes, "crypto_material")).digest()),
      new Uint8Array(createHash("sha256").update(sectionBytes(bytes, "device_evidence")).digest()),
    );
    expect(doc.expectedReportData()).toEqual(want);
  });
});

function sectionBytes(docBytes: Uint8Array, member: string): Uint8Array {
  const root = strictParse(docBytes) as JsonObject;
  return new Uint8Array(Buffer.from(root.get(member) as string, "base64"));
}
