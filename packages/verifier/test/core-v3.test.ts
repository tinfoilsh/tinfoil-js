import { describe, it, expect, vi } from "vitest";
import {
  UsageError,
  Verifier,
  Verification,
  randomNonce,
  parseReference,
} from "../src/index.js";
import {
  parseJSON,
  utf8,
  base64,
  hex,
  sha256,
  unbase64,
} from "../src/encoding.js";
import {
  computeReportData,
  parseDocument,
  KEY_TLS,
  KEY_HPKE,
  COLLATERALS_V3,
  FORMAT,
  decodeCollateral,
} from "../src/document.js";
import { DEFAULT_SIGNING_KEY } from "../src/approvals.js";
import { runtimePin, decodeRuntimeManifest, parseRuntimeManifest, MAX_ARTIFACT_SIZE } from "../src/runtime.js";
import keyVectors from "./fixtures/attested-keys-vectors.json";
const nonce = new Uint8Array(32);
async function document(
  items: unknown[] = [],
  devices: unknown[] = [],
): Promise<any> {
  const crypto = base64(
      utf8(
        JSON.stringify({
          format: "https://tinfoil.sh/crypto-material/v1",
          items,
        }),
      ),
    ),
    device = base64(
      utf8(
        JSON.stringify({
          format: "https://tinfoil.sh/device-evidence/v1",
          items: devices,
        }),
      ),
    );
  const ch = await sha256(unbase64(crypto)),
    dh = await sha256(unbase64(device));
  return {
    format: "https://tinfoil.sh/predicate/attestation/v3",
    challenge: {
      nonce: hex(nonce),
      report_data: hex(await computeReportData(nonce, ch, dh)),
      report_data_algorithm: "https://tinfoil.sh/report-data/v1",
    },
    cpu_evidence: {
      format: "https://tinfoil.sh/format/sev-snp-report/v1",
      report_base64: "AA==",
      endorsed: {
        crypto_material_hash: hex(ch),
        device_evidence_hash: hex(dh),
      },
    },
    crypto_material: crypto,
    device_evidence: device,
    collateral: [],
  };
}
describe("strict v3 trust boundaries", () => {
  it("rejects duplicate keys in opaque nested members and escaped aliases", () => {
    for (const input of [
      '{"x":{"a":1,"a":2}}',
      '{"a":1,"\\u0061":2}',
      '{"x":0} {}',
      '{"x":"\\ud800"}',
      "\uFEFF{}",
    ])
      expect(() => parseJSON(input)).toThrow();
    expect(() => parseJSON(new Uint8Array([0x22, 0xff, 0x22]))).toThrow();
  });
  it("preserves 64-bit policy integers exactly", () =>
    expect(parseJSON('{"m":18446744073709551615}').m).toBe(
      18446744073709551615n,
    ));
  it("does not mutate object prototypes", () => {
    const o = parseJSON('{"__proto__":{"polluted":true}}');
    expect(Object.getPrototypeOf(o)).toBeNull();
    expect(({} as any).polluted).toBeUndefined();
  });
  it("rejects noncanonical base64 encodings", () => {
    for (const s of ["AB==", "AAA", "AA==\n", "_-=="])
      expect(() => unbase64(s)).toThrow();
  });
  it("checks exact endorsed bytes and caller nonce", async () => {
    const d = await document();
    await expect(
      parseDocument(utf8(JSON.stringify(d)), nonce),
    ).resolves.toHaveProperty("cryptoMaterial", []);
    d.crypto_material = base64(
      utf8('{ "format":"https://tinfoil.sh/crypto-material/v1","items":[]}'),
    );
    await expect(parseDocument(utf8(JSON.stringify(d)), nonce)).rejects.toThrow(
      "hash",
    );
  });
  it("accepts trailing JSON whitespace around an otherwise valid envelope", async () => {
    const d = await document();
    await expect(
      parseDocument(utf8(JSON.stringify(d) + "\n \t\r"), nonce),
    ).resolves.toBeDefined();
  });
  it("rejects missing, malformed and mismatched challenge fields", async () => {
    for (const mutation of [
      (d: any) => {
        delete d.challenge.nonce;
      },
      (d: any) => {
        delete d.challenge.report_data;
      },
      (d: any) => {
        delete d.challenge.report_data_algorithm;
      },
      (d: any) => {
        d.challenge.nonce = "00".repeat(31);
      },
      (d: any) => {
        d.challenge.nonce = "AA".repeat(32);
      },
      (d: any) => {
        d.challenge.nonce = "01".repeat(32);
      },
      (d: any) => {
        d.challenge.report_data_algorithm += "/unknown";
      },
      (d: any) => {
        d.challenge.report_data = "00".repeat(63);
      },
      (d: any) => {
        d.challenge.report_data = "00".repeat(64);
      },
    ]) {
      const d = await document();
      mutation(d);
      await expect(
        parseDocument(utf8(JSON.stringify(d)), nonce),
      ).rejects.toThrow();
    }
  });
  it("binds the original device section bytes even when JSON meaning is unchanged", async () => {
    const d = await document(
      [],
      [
        {
          id: "optional",
          kind: "custom",
          vendor: "example",
          format: "https://example.test/device/v1",
          evidence: {},
        },
      ],
    );
    const section = parseJSON(unbase64(d.device_evidence));
    d.device_evidence = base64(utf8(JSON.stringify(section, null, 2)));
    await expect(parseDocument(utf8(JSON.stringify(d)), nonce)).rejects.toThrow(
      "hash",
    );
  });
  it("preserves arbitrary keys without requiring an HTTP key pair", async () => {
    const items = [
      { id: "custom", format: "https://example.test/key/v1", data: "ff" },
    ];
    const d = await document(items);
    expect(
      (await parseDocument(utf8(JSON.stringify(d)), nonce)).cryptoMaterial,
    ).toEqual(items);
  });
  it("rejects malformed known keys regardless of their id", async () => {
    for (const format of [KEY_TLS, KEY_HPKE]) {
      const d = await document([{ id: "arbitrary", format, data: "ff" }]);
      await expect(
        parseDocument(utf8(JSON.stringify(d)), nonce),
      ).rejects.toThrow();
    }
  });
  it("rejects duplicate key ids and unknown envelope members", async () => {
    const item = { id: "x", format: KEY_TLS, data: "00".repeat(32) };
    const d = await document([item, item]);
    await expect(parseDocument(utf8(JSON.stringify(d)), nonce)).rejects.toThrow(
      "Duplicate",
    );
    const unknown = await document();
    unknown.extra = true;
    await expect(
      parseDocument(utf8(JSON.stringify(unknown)), nonce),
    ).rejects.toThrow("Unknown");
  });
  it("preserves optional devices but rejects malformed or reserved device entries", async () => {
    const device = {
      id: "gpu-0",
      kind: "gpu",
      vendor: "example",
      format: "https://example.test/device/v1",
      evidence: { arbitrary: true },
    };
    const d = await document([], [device]);
    expect(
      (await parseDocument(utf8(JSON.stringify(d)), nonce)).deviceEvidence,
    ).toEqual([device]);
    for (const devices of [
      [{ ...device, id: "cpu" }],
      [{ ...device, evidence: "opaque" }],
      [{ ...device, vendor: "" }],
      [device, device],
    ]) {
      const invalid = await document([], devices);
      await expect(
        parseDocument(utf8(JSON.stringify(invalid)), nonce),
      ).rejects.toThrow();
    }
  });
  it("decodes malformed known collateral even when not selected", async () => {
    const d = await document();
    d.collateral = [
      {
        id: "unused",
        role: "endorsement",
        format: FORMAT["amd-crl"],
        subjects: ["device"],
        data: { crl_der_base64: "bad" },
      },
    ];
    await expect(
      parseDocument(utf8(JSON.stringify(d)), nonce),
    ).rejects.toThrow();
  });
  it("rejects invalid UTF-8 and BOMs inside either endorsed section", async () => {
    for (const section of ["crypto_material", "device_evidence"]) {
      const original = await document();
      await expect(parseDocument(utf8(JSON.stringify(original)), nonce)).resolves.toBeDefined();
      const valid = unbase64(original[section]);
      for (const prefix of [new Uint8Array([0xff]), utf8("\uFEFF")]) {
        const d = structuredClone(original);
        const bytes = new Uint8Array(prefix.length + valid.length);
        bytes.set(prefix); bytes.set(valid, prefix.length);
        d[section] = base64(bytes);
        const ch = await sha256(unbase64(d.crypto_material));
        const dh = await sha256(unbase64(d.device_evidence));
        d.cpu_evidence.endorsed.crypto_material_hash = hex(ch);
        d.cpu_evidence.endorsed.device_evidence_hash = hex(dh);
        d.challenge.report_data = hex(await computeReportData(nonce, ch, dh));
        const parsed = parseDocument(utf8(JSON.stringify(d)), nonce);
        if (prefix[0] === 0xff) await expect(parsed).rejects.toBeInstanceOf(TypeError);
        else await expect(parsed).rejects.toThrow("Invalid JSON value");
      }
    }
  });
  it("rejects unknown fields in every known collateral data schema", () => {
    const reference = { digest: "ab".repeat(32), sigstore_bundle: {} };
    const cases = [
      ["vcek", "endorsement", "amd-vcek", {}],
      ["crl", "endorsement", "amd-crl", {}],
      ["pcs", "endorsement", "intel-pcs", { responses: [] }],
      ["code", "reference-values", "sigstore-code", reference],
      ["platform", "reference-values", "sigstore-platform", reference],
      [
        "code-freshness",
        "reference-values",
        "sigstore-freshness",
        { sigstore_bundle: {} },
      ],
      [
        "runtime-freshness",
        "reference-values",
        "artifact-freshness",
        { sigstore_bundle: {} },
      ],
      [
        "tinfoil-config",
        "reference-values",
        "config-endorsement",
        {
          config_base64: "YQ==",
          endorsement_ref: "sha256:" + "ab".repeat(32),
          sigstore_bundle: {},
        },
      ],
      [
        "tinfoil-config",
        "reference-values",
        "config",
        { config_base64: "YQ==" },
      ],
      [
        "runtime",
        "reference-values",
        "igvm-runtime",
        {
          repo: "tinfoilsh/cvmimage",
          tag: "v1.0.0",
          digest: "ab".repeat(32),
          manifest_base64: "YQ==",
          sigstore_bundle: {},
        },
      ],
    ] as const;
    for (const [id, role, format, data] of cases) {
      const entry = { id, role, format: FORMAT[format], data };
      expect(() => decodeCollateral([entry])).not.toThrow();
      expect(() =>
        decodeCollateral([{ ...entry, data: { ...data, Unexpected: true } }]),
      ).toThrow("Unknown member");
    }
    expect(() =>
      decodeCollateral([
        {
          id: "pcs",
          role: "endorsement",
          format: FORMAT["intel-pcs"],
          data: { responses: [{ unexpected: true }] },
        },
      ]),
    ).toThrow("Unknown member");
  });
  it("rejects unknown fields in every fixed endorsed-envelope object", async () => {
    const device = {
      id: "device",
      kind: "custom",
      vendor: "example",
      format: "https://example.test/device/v1",
      evidence: {},
    };
    for (const path of [
      "challenge",
      "cpu_evidence",
      "endorsed",
      "crypto_material",
      "crypto_item",
      "device_evidence",
      "device_item",
    ]) {
      const d = await document(
        [{ id: "tls", format: KEY_TLS, data: "00".repeat(32) }],
        [device],
      );
      if (path === "challenge" || path === "cpu_evidence")
        d[path].unexpected = true;
      else if (path === "endorsed") d.cpu_evidence.endorsed.unexpected = true;
      else {
        const name = path.startsWith("crypto")
          ? "crypto_material"
          : "device_evidence";
        const section = parseJSON(unbase64(d[name]));
        (path.endsWith("item") ? section.items[0] : section).unexpected = true;
        d[name] = base64(utf8(JSON.stringify(section)));
      }
      await expect(
        parseDocument(utf8(JSON.stringify(d)), nonce),
      ).rejects.toThrow("Unknown member");
    }
  });
  it("selects only matching CPU subjects and rejects ambiguous collateral structure", () => {
    const entry = {
      id: "crl",
      role: "endorsement",
      format: FORMAT["amd-crl"],
      data: { crl_der_base64: "AA==" },
    };
    expect(
      decodeCollateral([{ ...entry, subjects: ["other"] }]).cpu.amdCrl,
    ).toBeUndefined();
    expect(
      decodeCollateral([{ ...entry, subjects: ["cpu"] }]).cpu.amdCrl?.crlDer,
    ).toEqual(new Uint8Array([0]));
    for (const entries of [
      [entry, entry],
      [{ ...entry, role: "unknown" }],
      [{ ...entry, subjects: ["cpu", "cpu"] }],
      [{ ...entry, subjects: [42] }],
    ])
      expect(() => decodeCollateral(entries)).toThrow();
    const reference = {
      id: "first",
      role: "reference-values",
      format: FORMAT["sigstore-code"],
      data: { digest: "ab".repeat(32), sigstore_bundle: {} },
    };
    const second = {
      ...reference,
      id: "second",
      data: { ...reference.data, digest: "cd".repeat(32) },
    };
    expect(decodeCollateral([reference, second]).code?.digest).toBe(
      reference.data.digest,
    );
    expect(decodeCollateral([second, reference]).code?.digest).toBe(
      second.data.digest,
    );
    expect(() =>
      decodeCollateral([
        reference,
        { ...second, data: { ...second.data, unexpected: true } },
      ]),
    ).toThrow();
  });
  it.each(keyVectors)(
    "matches the published $algorithm attested-key hash and REPORT_DATA vector",
    async (vector) => {
      const d = await document();
      d.crypto_material = vector.crypto_material;
      d.device_evidence = vector.device_evidence;
      d.cpu_evidence.endorsed = {
        crypto_material_hash: vector.crypto_material_hash,
        device_evidence_hash: vector.device_evidence_hash,
      };
      d.challenge.nonce = vector.nonce;
      d.challenge.report_data = vector.report_data;
      const expectedNonce = Uint8Array.from(vector.nonce.match(/../g)!, (h) =>
        Number.parseInt(h, 16),
      );
      const parsed = await parseDocument(
        utf8(JSON.stringify(d)),
        expectedNonce,
      );
      expect(parsed.cryptoMaterial).toEqual([vector.item]);
      expect(hex(parsed.expectedReportData)).toBe(vector.report_data);
    },
  );
  it("rejects cross-profile reference collateral", async () => {
    const d = await document();
    d.collateral_format = COLLATERALS_V3;
    d.collateral = [
      {
        id: "code",
        role: "reference-values",
        format: FORMAT["sigstore-code"],
        data: { digest: "ab".repeat(32), sigstore_bundle: {} },
      },
    ];
    await expect(parseDocument(utf8(JSON.stringify(d)), nonce)).rejects.toThrow(
      "profile",
    );
  });
  it("requires 32 random nonce bytes and classifies caller input", async () => {
    expect(randomNonce()).toHaveLength(32);
    await expect(
      new Verifier().verify(new Uint8Array(), new Uint8Array(31), "a/b"),
    ).rejects.toBeInstanceOf(UsageError);
    await expect(
      new Verifier().verify(utf8("{}"), nonce, "a/b"),
    ).rejects.toMatchObject({ name: "VerificationError", layer: "envelope" });
  });
  it("prevents construction and forgery of verified results", () => {
    expect(() => Reflect.construct(Verification, [])).toThrow(UsageError);
    const fake = Object.create(Verification.prototype);
    expect(() => fake.cryptoMaterialData("tls", KEY_TLS)).toThrow(UsageError);
  });
  it("copies and validates configured keys, pins and trust conflicts", () => {
    const pins = { type: "sev-snp" as const, launch: "AA".repeat(48) };
    const key = new Uint8Array(DEFAULT_SIGNING_KEY);
    const v = new Verifier({ configSigningKeys: [key], pinnedRegisters: pins });
    key.fill(0);
    pins.launch = "bb".repeat(48);
    expect(v.pinnedRegisters).toEqual({
      type: "sev-snp",
      launch: "aa".repeat(48),
    });
    expect(Object.isFrozen(v)).toBe(true);
    expect(() => new Verifier({ configSigningKeys: [] })).toThrow(UsageError);
    expect(
      () =>
        new Verifier({
          configSigningKeys: [DEFAULT_SIGNING_KEY],
          configAuthorizer: () => {},
        }),
    ).toThrow(UsageError);
    expect(
      () => new Verifier({ pinnedRegisters: { type: "tdx", mrtd: "ab" } }),
    ).toThrow(UsageError);
    expect(() => new Verifier({ freshnessMaxAgeMs: -1 })).toThrow(UsageError);
  });
  it("rejects unknown root and clock constructor seams", () => {
    expect(() => new Verifier({ sigstoreRoot: {} } as any)).toThrow(UsageError);
    expect(() => new Verifier({ verificationTime: new Date() } as any)).toThrow(
      UsageError,
    );
  });
  it("extracts exact runtime pins and rejects YAML duplicate/doc ambiguity", () => {
    const digest = "aa".repeat(32);
    expect(
      runtimePin(utf8(`cvm-version: 1.2.3+gpu@sha256:${digest}\n`)),
    ).toEqual({ repo: "tinfoilsh/cvmimage", tag: "v1.2.3+gpu", digest });
    for (const value of [
      `cvm-version: 1.2@sha256:${digest}`,
      `cvm-version: 1.2.3@sha256:${digest}\n---\n`,
      `cvm-version: bad\ncvm-version: 1.2.3@sha256:${digest}`,
    ])
      expect(() => runtimePin(utf8(value))).toThrow();
  });
  it("bounds config and runtime manifests before parsing", () => {
    for (const bytes of [new Uint8Array(), new Uint8Array((1 << 20) + 1)]) {
      expect(() => runtimePin(bytes)).toThrow("Config size");
      expect(() => decodeRuntimeManifest(bytes)).toThrow(
        "Runtime manifest size",
      );
    }
  });
  it("validates reference syntax and digest case", () => {
    expect(
      parseReference("owner/repo@v1.0.0@sha256:" + "ab".repeat(32)),
    ).toEqual({ repo: "owner/repo", tag: "v1.0.0", digest: "ab".repeat(32) });
    for (const r of [
      "",
      "owner/repo@main@other",
      "owner/repo@sha256:" + "AB".repeat(32),
    ])
      expect(() => parseReference(r)).toThrow(UsageError);
  });
});

it("rejects oversized runtime manifests before hashing", async () => {
  const digest = vi.spyOn(crypto.subtle, "digest");
  try {
    await expect(parseRuntimeManifest(new Uint8Array(MAX_ARTIFACT_SIZE + 1), { repo: "tinfoilsh/cvmimage", tag: "v1.0.0", digest: "00".repeat(32) })).rejects.toThrow("Runtime manifest size outside bounds");
    expect(digest).not.toHaveBeenCalled();
  } finally { digest.mockRestore(); }
});
