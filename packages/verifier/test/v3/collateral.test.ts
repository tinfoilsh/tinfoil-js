/**
 * Tests for collateral decoding: the collateral set built from wire entries
 * (collateral.ts), config endorsement entries (config.ts) and runtime and
 * platform entries (runtime.ts).
 *
 * Entries carry their data as JSON text and go through the same path parse
 * uses (strict JSON, decodeEntries, decode). Data that is not valid JSON at
 * all ("{bad", duplicate members, trailing values) is therefore rejected by
 * the strict JSON parser rather than by decode; the outcome is the same.
 */
import { describe, expect, it } from "vitest";
import {
  AMD_CRL_V1_FORMAT,
  AMD_VCEK_V1_FORMAT,
  ARTIFACT_FRESHNESS_V1_FORMAT,
  CONFIG_ENDORSEMENT_V1_FORMAT,
  CONFIG_ID,
  CONFIG_V1_FORMAT,
  configPlatform,
  decode,
  decodeEntries,
  FRESHNESS_ID_CODE,
  FRESHNESS_ID_PLATFORM,
  FRESHNESS_ID_RUNTIME,
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
  PLATFORM_ID,
  RUNTIME_ID,
  RUNTIME_REPO,
  RUNTIME_V1_FORMAT,
  validateRuntimeReference,
  type RuntimeReference,
} from "../../src/v3/document/collateral/runtime.js";
import { strictParse } from "../../src/v3/internal/json/index.js";
import { b64, marshalEntries, type WireEntry } from "./helpers/builder.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const q = (s: string): string => JSON.stringify(s);

/** Decodes entries as parse does; throws on any rejection. */
function decodeWire(entries: WireEntry[]): CollateralSet {
  return decode(decodeEntries(strictParse(enc(marshalEntries(entries)))));
}

function thrown(f: () => unknown): Error {
  try {
    f();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected an error");
}

/** A cpu endorsement entry with the given JSON payload. */
const testEntry = (id: string, format: string, data: string): WireEntry => ({
  id,
  role: ROLE_ENDORSEMENT,
  format,
  subjects: [SUBJECT_CPU],
  data,
});
const vcekData = (der: string, chain: string) => `{"vcek_der_base64":${q(der)},"cert_chain_pem":${q(chain)}}`;
const crlData = (der: string) => `{"crl_der_base64":${q(der)}}`;
const pcsData = (responses: { url: string; headers?: Record<string, string[]>; body: string }[]) =>
  `{"responses":[${responses
    .map((r) => `{"url":${q(r.url)},"headers":${JSON.stringify(r.headers ?? {})},"body_base64":${q(r.body)}}`)
    .join(",")}]}`;

const sevEntries = (): WireEntry[] => [
  testEntry("cpu-endorsement", AMD_VCEK_V1_FORMAT, vcekData(b64("vcek der"), "chain")),
  testEntry("cpu-crl", AMD_CRL_V1_FORMAT, crlData(b64("crl der"))),
];

// ---------------------------------------------------------------- collateral set decoding

describe("collateral set decoding", () => {
  it("decodes SEV-SNP collateral (vcek and crl)", () => {
    expect(decodeWire(sevEntries()).cpu).toEqual({
      amdVcek: { vcekDer: enc("vcek der"), certChainPem: "chain" },
      amdCrl: { crlDer: enc("crl der") },
    });
  });

  it("decodes TDX collateral (intel-pcs responses)", () => {
    const url = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity";
    const headers = { "Sgx-Enclave-Identity-Issuer-Chain": ["chain"] };
    const body = enc(`{"enclaveIdentity":{}}`);
    const set = decodeWire([testEntry("pcs", INTEL_PCS_V1_FORMAT, pcsData([{ url, headers, body: b64(body) }]))]);
    expect(set.cpu).toEqual({
      intelPcs: { responses: [{ url, headers: new Map(Object.entries(headers)), body }] },
    });
  });

  it("an empty array decodes to an empty set", () => {
    const set = decodeWire([]);
    expect(set.cpu).toEqual({});
    expect(set.sigstoreCode).toBeUndefined();
    expect(set.sigstorePlatform).toBeUndefined();
    expect(set.freshness.size).toBe(0);
  });

  it("cpu collateral requires the cpu subject", () => {
    const entries = sevEntries();
    entries[0]!.subjects = ["gpu0"];
    const set = decodeWire(entries);
    expect(set.cpu.amdVcek).toBeUndefined();
    expect(set.cpu.amdCrl).toBeDefined();
  });

  describe("rejects a malformed entry list", () => {
    const entry: WireEntry = {
      id: "crl",
      role: ROLE_ENDORSEMENT,
      format: "https://tinfoil.sh/collateral/unknown/v9",
      data: `{}`,
    };
    const unknownRole = { ...entry, role: "unknown" };
    // An empty data string means the data member is absent.
    const withData = (data: string): WireEntry[] => [{ ...entry, data: data === "" ? undefined : data }];
    it.each<[string, WireEntry[], string | undefined]>([
      ["missing id", [{ role: ROLE_ENDORSEMENT, format: AMD_CRL_V1_FORMAT }], "collateral entry 0 is incomplete"],
      ["missing format", [entry, { id: "x", role: ROLE_ENDORSEMENT }], "collateral entry 1 is incomplete"],
      ["duplicate id", [entry, entry], `duplicate collateral entry id "crl"`],
      ["unknown role", [unknownRole], `collateral entry "crl" has unknown role "unknown"`],
      ["missing data", withData(""), `collateral entry "crl" data is not a valid JSON object`],
      ["null data", withData("null"), `collateral entry "crl" data is not a valid JSON object`],
      ["array data", withData("[]"), `collateral entry "crl" data is not a valid JSON object`],
      ["string data", withData(`"x"`), `collateral entry "crl" data is not a valid JSON object`],
      // Not valid JSON: the strict parser rejects the array before decode sees it.
      ["malformed object", withData(`{bad`), undefined],
      ["duplicate member", withData(`{"a":1,"a":2}`), undefined],
      ["trailing value", withData(`{} {}`), undefined],
    ])("%s", (_name, entries, wantErr) => {
      const err = thrown(() => decodeWire(entries));
      if (wantErr !== undefined) expect(err.message).toContain(wantErr);
    });
  });

  describe("rejects malformed data of known formats", () => {
    const good = sevEntries();
    const unusedBody = b64(`{"unused":true}`);
    it.each<[string, WireEntry[], string]>([
      [
        "malformed intel-pcs",
        [testEntry("pcs", INTEL_PCS_V1_FORMAT, `{"unknown":1}`)],
        `parsing intel-pcs collateral entry "pcs"`,
      ],
      [
        "entry for another subject",
        [{ ...testEntry("vcek", AMD_VCEK_V1_FORMAT, `{"unknown":1}`), subjects: ["gpu0"] }],
        `parsing amd-vcek collateral entry "vcek"`,
      ],
      [
        "non-canonical vcek",
        [testEntry("cpu-endorsement", AMD_VCEK_V1_FORMAT, vcekData(b64("vcek der") + "\n", "chain")), good[1]!],
        `amd-vcek collateral entry "cpu-endorsement": vcek_der_base64 is not canonical base64`,
      ],
      [
        "non-canonical crl",
        [good[0]!, testEntry("cpu-crl", AMD_CRL_V1_FORMAT, crlData(b64("crl der") + "\r\n"))],
        `amd-crl collateral entry "cpu-crl": crl_der_base64 is not canonical base64`,
      ],
      [
        "invalid crl base64",
        [testEntry("cpu-crl", AMD_CRL_V1_FORMAT, crlData("not base64!"))],
        `amd-crl collateral entry "cpu-crl": decoding crl_der_base64`,
      ],
      [
        "unused pcs response",
        [
          testEntry(
            "pcs",
            INTEL_PCS_V1_FORMAT,
            pcsData([
              {
                url: "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000",
                body: b64(`{"tcbInfo":{}}`),
              },
              { url: "https://example.com/never-requested", body: unusedBody.slice(0, 4) + "\n" + unusedBody.slice(4) },
            ]),
          ),
        ],
        `intel-pcs collateral entry "pcs" response 1: body_base64 is not canonical base64`,
      ],
      [
        "malformed sigstore reference",
        [{ id: "code", role: ROLE_REFERENCE_VALUES, format: SIGSTORE_CODE_V1_FORMAT, data: `{"repo":"org/code","unknown":1}` }],
        `parsing ${SIGSTORE_CODE_V1_FORMAT} collateral entry "code"`,
      ],
      [
        "malformed freshness witness",
        [{ id: FRESHNESS_ID_CODE, role: ROLE_REFERENCE_VALUES, format: SIGSTORE_FRESHNESS_V1_FORMAT, data: `{"unknown":1}` }],
        `parsing ${SIGSTORE_FRESHNESS_V1_FORMAT} collateral entry "code-freshness"`,
      ],
    ])("%s", (_name, entries, wantErr) => {
      const err = thrown(() => decodeWire(entries));
      expect(err.message).toContain(wantErr);
      expect(err).not.toBeInstanceOf(NotFoundError);
    });
  });

  it("ignores entries of unknown formats and of a format under the wrong role", () => {
    for (const entry of [
      { id: "future", role: ROLE_ENDORSEMENT, format: "https://tinfoil.sh/collateral/unknown/v9", data: `{"x":1}` },
      { id: "misrole", role: ROLE_REFERENCE_VALUES, format: AMD_VCEK_V1_FORMAT, data: `{"unknown":1}` },
    ]) {
      expect(decodeWire([entry]).cpu, entry.id).toEqual({});
    }
  });

  it("selects the first entry per purpose", () => {
    const pcs = (id: string, url: string) => testEntry(id, INTEL_PCS_V1_FORMAT, pcsData([{ url, body: b64("body") }]));
    const ref = (id: string, format: string, repo: string): WireEntry => ({
      id,
      role: ROLE_REFERENCE_VALUES,
      format,
      data: `{"repo":${q(repo)},"tag":"","digest":"ab","sigstore_bundle":{}}`,
    });
    const set = decodeWire([
      testEntry("vcek-1", AMD_VCEK_V1_FORMAT, vcekData(b64("first vcek"), "chain")),
      testEntry("vcek-2", AMD_VCEK_V1_FORMAT, vcekData(b64("second vcek"), "chain")),
      testEntry("crl-1", AMD_CRL_V1_FORMAT, crlData(b64("first crl"))),
      testEntry("crl-2", AMD_CRL_V1_FORMAT, crlData(b64("second crl"))),
      pcs("pcs-1", "https://first.example"),
      pcs("pcs-2", "https://second.example"),
      ref("code-1", SIGSTORE_CODE_V1_FORMAT, "org/first"),
      ref("code-2", SIGSTORE_CODE_V1_FORMAT, "org/second"),
      ref("platform-1", SIGSTORE_PLATFORM_V1_FORMAT, "org/first-platform"),
      ref("platform-2", SIGSTORE_PLATFORM_V1_FORMAT, "org/second-platform"),
    ]);
    expect(set.cpu.amdVcek!.vcekDer).toEqual(enc("first vcek"));
    expect(set.cpu.amdCrl!.crlDer).toEqual(enc("first crl"));
    expect(set.cpu.intelPcs!.responses[0]!.url).toBe("https://first.example");
    expect(set.sigstoreCode!.repo).toBe("org/first");
    expect(set.sigstorePlatform!.repo).toBe("org/first-platform");
  });

  it("keys freshness witnesses by entry id", () => {
    const witness = (id: string, bundle: string): WireEntry => ({
      id,
      role: ROLE_REFERENCE_VALUES,
      format: SIGSTORE_FRESHNESS_V1_FORMAT,
      data: `{"sigstore_bundle":${bundle}}`,
    });
    const set = decodeWire([witness(FRESHNESS_ID_CODE, `{"a":1}`), witness(FRESHNESS_ID_PLATFORM, `{"b":2}`)]);
    expect(set.freshness).toEqual(
      new Map([
        [FRESHNESS_ID_CODE, { format: SIGSTORE_FRESHNESS_V1_FORMAT, bundle: strictParse(enc(`{"a":1}`)) }],
        [FRESHNESS_ID_PLATFORM, { format: SIGSTORE_FRESHNESS_V1_FORMAT, bundle: strictParse(enc(`{"b":2}`)) }],
      ]),
    );
  });

  describe("sigstore references require a bundle and a digest", () => {
    const ref = (format: string, data: string): WireEntry => ({ id: "ref", role: ROLE_REFERENCE_VALUES, format, data });
    it.each<[string, WireEntry, string]>([
      ["code without bundle", ref(SIGSTORE_CODE_V1_FORMAT, `{"repo":"o/r","tag":"v1","digest":"ab"}`), "is missing sigstore_bundle"],
      [
        "code with null bundle",
        ref(SIGSTORE_CODE_V1_FORMAT, `{"repo":"o/r","tag":"v1","digest":"ab","sigstore_bundle":null}`),
        "is missing sigstore_bundle",
      ],
      ["platform without digest", ref(SIGSTORE_PLATFORM_V1_FORMAT, `{"repo":"o/r","tag":"v1","sigstore_bundle":{}}`), "is missing digest"],
      [
        "code with empty digest",
        ref(SIGSTORE_CODE_V1_FORMAT, `{"repo":"o/r","tag":"v1","digest":"","sigstore_bundle":{}}`),
        "is missing digest",
      ],
      ["freshness without bundle", ref(SIGSTORE_FRESHNESS_V1_FORMAT, `{}`), "is missing sigstore_bundle"],
      ["freshness with null bundle", ref(SIGSTORE_FRESHNESS_V1_FORMAT, `{"sigstore_bundle":null}`), "is missing sigstore_bundle"],
    ])("%s", (_name, entry, wantErr) => {
      expect(() => decodeWire([entry])).toThrow(wantErr);
    });
    it.each<[string, WireEntry]>([
      [
        "empty tag and repo",
        ref(SIGSTORE_CODE_V1_FORMAT, `{"repo":"","tag":"","digest":"ab","sigstore_bundle":{"mediaType":"x"}}`),
      ],
      ["present invalid bundle", ref(SIGSTORE_FRESHNESS_V1_FORMAT, `{"sigstore_bundle":{}}`)],
    ])("accepts %s", (_name, entry) => {
      expect(() => decodeWire([entry])).not.toThrow();
    });
  });

  // TS collateral types are plain readonly interfaces with no Clone methods.
  it.skip("PCS response clones are deep (no clone methods in TS)", () => {});
  it.skip("clones preserve unset fields (no clone methods in TS)", () => {});
});

// ---------------------------------------------------------------- config collateral

describe("config collateral", () => {
  it("decodes plain config collateral and rejects an endorsement in it", () => {
    const entry: WireEntry = {
      id: CONFIG_ID,
      role: ROLE_REFERENCE_VALUES,
      format: CONFIG_V1_FORMAT,
      data: `{"config_base64":"Y29uZmln"}`,
    };
    const set = decodeWire([entry]);
    expect(set.config!.config).toEqual(enc("config"));
    expect(set.config!.reference).toBe("");
    expect(set.config!.bundle).toBeUndefined();
    expect(() => decodeWire([entry, entry])).toThrow();
    expect(() => decodeWire([{ ...entry, format: CONFIG_ENDORSEMENT_V1_FORMAT }])).toThrow("endorsement_ref");
    expect(() =>
      decodeWire([{ ...entry, data: `{"config_base64":"Y29uZmln","sigstore_bundle":{}}` }]),
    ).toThrow("cannot contain an endorsement");
  });

  describe("config endorsement", () => {
    const config = "cvm-version: 1.0.0\n";
    const reference = "sha256:" + "ab".repeat(32);
    const data = `{"endorsement_ref":${q(reference)},"config_base64":${q(b64(config))},"sigstore_bundle":{"mediaType":"test"}}`;
    const entry: WireEntry = { id: CONFIG_ID, role: ROLE_REFERENCE_VALUES, format: CONFIG_ENDORSEMENT_V1_FORMAT, data };

    it("decodes", () => {
      const got = decodeWire([entry]).config;
      expect(got).toBeDefined();
      expect(got!.reference).toBe(reference);
      expect(got!.config).toEqual(enc(config));
      expect(got!.bundle).toEqual(strictParse(enc(`{"mediaType":"test"}`)));
    });

    it.each<[string, (entries: WireEntry[]) => WireEntry[]]>([
      ["wrong role", (e) => [{ ...e[0]!, role: ROLE_ENDORSEMENT }]],
      ["wrong format", (e) => [{ ...e[0]!, format: SIGSTORE_CODE_V1_FORMAT }]],
      ["wrong id", (e) => [{ ...e[0]!, id: "other" }]],
      ["duplicate", (e) => [...e, entry]],
      ["ambiguous format", (e) => [...e, { ...entry, id: "other" }]],
      ["noncanonical base64", (e) => [{ ...e[0]!, data: data.replace(`"config_base64":"`, `"config_base64":"\\n`) }]],
      ["empty config", (e) => [{ ...e[0]!, data: data.replace(b64(config), "") }]],
      ["missing config", (e) => [{ ...e[0]!, data: data.replace(`"config_base64":${q(b64(config))},`, "") }]],
      ["bad reference", (e) => [{ ...e[0]!, data: data.replace(reference, "sha256:bad") }]],
      ["unknown member", (e) => [{ ...e[0]!, data: `{"unknown":true,` + data.slice(1) }]],
      ["duplicate member", (e) => [{ ...e[0]!, data: `{"endorsement_ref":"ignored",` + data.slice(1) }]],
      ["missing bundle", (e) => [{ ...e[0]!, data: data.replace(`{"mediaType":"test"}`, "null") }]],
    ])("%s", (_name, mutate) => {
      const entries = mutate([entry]);
      expect(entries).not.toEqual([entry]);
      expect(() => decodeWire(entries)).toThrow();
    });
  });
});

// ---------------------------------------------------------------- runtime and platform collateral

describe("runtime and platform collateral", () => {
  it("validates runtime references", () => {
    const valid: RuntimeReference = { repo: RUNTIME_REPO, tag: "v0.15.0-rc.1", digest: "ab".repeat(32) };
    expect(() => validateRuntimeReference(valid)).not.toThrow();
    for (const bad of [
      { ...valid, repo: "other/runtime" },
      { ...valid, tag: "0.15.0" },
      { ...valid, tag: "v0.15" },
      { ...valid, tag: "v0.15.0+mini/other" },
      { ...valid, digest: valid.digest.toUpperCase() },
      { ...valid, digest: "ab" },
    ]) {
      expect(() => validateRuntimeReference(bad), JSON.stringify(bad)).toThrow();
    }
  });

  it("decodes runtime collateral and rejects a second runtime entry", () => {
    const ref: RuntimeReference = { repo: RUNTIME_REPO, tag: "v0.15.0", digest: "ab".repeat(32) };
    const manifest = `{"version":"v0.15.0"}`;
    const data = `{"repo":${q(ref.repo)},"tag":${q(ref.tag)},"digest":${q(ref.digest)},"manifest_base64":${q(b64(manifest))},"sigstore_bundle":{}}`;
    const entry: WireEntry = { id: RUNTIME_ID, role: ROLE_REFERENCE_VALUES, format: RUNTIME_V1_FORMAT, data };
    const got = decodeWire([entry]).runtime;
    expect(got).toBeDefined();
    expect({ repo: got!.repo, tag: got!.tag, digest: got!.digest }).toEqual(ref);
    expect(got!.manifest).toEqual(enc(manifest));
    expect(() => decodeWire([entry, { ...entry, id: "other-runtime" }])).toThrow("conflicting collateral");
  });

  describe("config platform reference", () => {
    const entry: WireEntry = {
      id: PLATFORM_ID,
      role: ROLE_REFERENCE_VALUES,
      format: SIGSTORE_PLATFORM_V1_FORMAT,
      data: `{"repo":"tinfoilsh/cvmimage","tag":"platform-v1.0.0","digest":"ab","sigstore_bundle":{}}`,
    };

    it("selects the platform reference", () => {
      // Bundles are shared ReadonlyMap JSON values by design, so only the
      // struct copy is checked.
      const set = decodeWire([entry]);
      const platform = configPlatform(set);
      expect(platform.repo).toBe("tinfoilsh/cvmimage");
      expect(platform.bundle).toEqual(new Map());
    });

    it.each<[string, (entries: WireEntry[]) => WireEntry[]]>([
      ["missing", () => []],
      ["wrong id", (e) => [{ ...e[0]!, id: "other" }]],
      ["wrong role", (e) => [{ ...e[0]!, role: ROLE_ENDORSEMENT }]],
      ["wrong format", (e) => [{ ...e[0]!, format: "https://tinfoil.sh/collateral/unknown/v1" }]],
      ["multiple references", (e) => [...e, { ...entry, id: "other" }]],
    ])("%s", (name, mutate) => {
      const set = decodeWire(mutate([entry]));
      if (name === "missing") {
        expect(() => configPlatform(set)).toThrow(NotFoundError);
      } else {
        expect(() => configPlatform(set)).toThrow("conflicting platform collateral");
      }
    });
  });

  describe("artifact freshness requires a reserved id", () => {
    for (const id of [FRESHNESS_ID_PLATFORM, FRESHNESS_ID_RUNTIME]) {
      const entry: WireEntry = {
        id,
        role: ROLE_REFERENCE_VALUES,
        format: ARTIFACT_FRESHNESS_V1_FORMAT,
        data: `{"sigstore_bundle":{}}`,
      };
      it(`${id} decodes`, () => {
        expect(decodeWire([entry]).freshness.get(id)!.format).toBe(ARTIFACT_FRESHNESS_V1_FORMAT);
      });
      it.each<[string, WireEntry]>([
        ["unknown id", { ...entry, id: "other" }],
        ["wrong role", { ...entry, role: ROLE_ENDORSEMENT }],
        ["missing bundle", { ...entry, data: `{}` }],
      ])(`${id}/%s`, (_name, changed) => {
        expect(() => decodeWire([changed])).toThrow();
      });
    }
    it("sigstore-freshness under the runtime id", () => {
      expect(() =>
        decodeWire([
          { id: FRESHNESS_ID_RUNTIME, role: ROLE_REFERENCE_VALUES, format: SIGSTORE_FRESHNESS_V1_FORMAT, data: `{"sigstore_bundle":{}}` },
        ]),
      ).toThrow("conflicting artifact freshness collateral");
    });
  });
});

describe("review regressions", () => {
  it("prefixes field type errors with the collateral entry", () => {
    for (const [format, data] of [
      [AMD_VCEK_V1_FORMAT, `{"vcek_der_base64":"","cert_chain_pem":1}`],
      [AMD_VCEK_V1_FORMAT, `{"vcek_der_base64":true,"cert_chain_pem":""}`],
    ] as const) {
      expect(() => decodeWire([testEntry("cpu-endorsement", format, data)])).toThrow(
        /collateral entry "cpu-endorsement"/,
      );
    }
  });
});
