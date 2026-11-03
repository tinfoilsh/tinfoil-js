/**
 * Port of tinfoil-go verify/internal/runtime/manifest_test.go. Test titles
 * are the Go test (and subtest) names.
 *
 * Go's tests json.Marshal a Manifest struct; here `manifestJson` renders the
 * same compact text in struct member order (nil pointers as null, as none of
 * the members carry omitempty). Go int fields are bigint in TS.
 *
 * The trailing describes add decode-level cases the Go tests do not cover;
 * each verdict was confirmed against Go 1.27 (encoding/json/v2, yaml.v3) with
 * a scratch program calling runtime.DecodeManifest / runtime.ConfigRuntime on
 * the same bytes.
 */
import { describe, expect, it } from "vitest";
import { RUNTIME_REPO, type RuntimeReference } from "../../src/v3/document/collateral/runtime.js";
import { sha256, toHex } from "../../src/v3/internal/bytes.js";
import { configRuntime } from "../../src/v3/internal/runtime/config.js";
import { decodeManifest, FORMAT_VERSION, MEASUREMENT_SIZE, parseManifest, type Manifest } from "../../src/v3/internal/runtime/manifest.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => new TextDecoder().decode(b);

/** A mutable mirror of Go's Manifest struct for building JSON (null = nil pointer). */
interface TdxLaunchSpec {
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
}
interface ManifestSpec {
  version: string;
  igvm: {
    format_version: number;
    snp_launch: { measurement: string } | null;
    tdx_launch: TdxLaunchSpec | null;
  } | null;
}

const measurement = "cd".repeat(MEASUREMENT_SIZE);
const zeroRegister = "0".repeat(MEASUREMENT_SIZE * 2);

/** Go validManifest() as a JSON-building spec. */
function validSpec(): ManifestSpec {
  return {
    version: "v0.15.0",
    igvm: {
      format_version: FORMAT_VERSION,
      snp_launch: { measurement },
      tdx_launch: { mrtd: measurement, rtmr0: zeroRegister, rtmr1: zeroRegister, rtmr2: zeroRegister, rtmr3: zeroRegister },
    },
  };
}

/** Go validManifest() as the parsed TS value. */
function validManifest(): Manifest {
  return {
    version: "v0.15.0",
    measurements: {
      formatVersion: BigInt(FORMAT_VERSION),
      snpLaunch: { measurement },
      tdxLaunch: { mrtd: measurement, rtmr0: zeroRegister, rtmr1: zeroRegister, rtmr2: zeroRegister, rtmr3: zeroRegister },
    },
  };
}

/** json.Marshal of the Go struct: compact, member order version, igvm{format_version, snp_launch, tdx_launch}. */
const manifestJson = (m: ManifestSpec): string => JSON.stringify(m);

/** Go manifestBytes: the JSON bytes and the pin whose digest is theirs. */
async function manifestBytes(m: ManifestSpec): Promise<[Uint8Array, RuntimeReference]> {
  const data = enc(manifestJson(m));
  return [data, { repo: RUNTIME_REPO, tag: "v0.15.0", digest: toHex(await sha256(data)) }];
}

async function rejects(p: Promise<unknown>, want?: string | RegExp): Promise<void> {
  if (want === undefined) await expect(p).rejects.toThrow();
  else await expect(p).rejects.toThrow(want);
}

// ---------------------------------------------------------------- manifest_test.go

describe("manifest_test.go", () => {
  describe("TestManifestRequiresCompleteSupportedMeasurements", () => {
    it("accepts the valid manifest under its pin", async () => {
      const [data, ref] = await manifestBytes(validSpec());
      expect(await parseManifest(data, ref)).toEqual(validManifest());
      const appended = new Uint8Array([...data, 0x0a]);
      await rejects(parseManifest(appended, ref), "digest pin");
    });

    const mutations: [string, (m: ManifestSpec) => void][] = [
      ["old manifest", (m) => (m.igvm = null)],
      ["unknown version", (m) => m.igvm!.format_version++],
      ["wrong release", (m) => (m.version = "v0.15.1")],
      ["missing SNP", (m) => (m.igvm!.snp_launch = null)],
      ["missing TDX", (m) => (m.igvm!.tdx_launch = null)],
      ["nonzero RTMR", (m) => (m.igvm!.tdx_launch!.rtmr2 = "ab".repeat(MEASUREMENT_SIZE))],
      ["missing RTMR", (m) => (m.igvm!.tdx_launch!.rtmr3 = "")],
      ["bad MRTD", (m) => (m.igvm!.tdx_launch!.mrtd = "bad")],
      ["uppercase SNP", (m) => (m.igvm!.snp_launch!.measurement = m.igvm!.snp_launch!.measurement.toUpperCase())],
    ];
    it.each(mutations)("%s", async (_name, mutate) => {
      const m = validSpec();
      mutate(m);
      const [data, ref] = await manifestBytes(m);
      await rejects(parseManifest(data, ref));
    });

    const prefixes: [string, string, boolean][] = [
      ["download metadata", `{"root":"host image digest",`, false],
      ["duplicate member", `{"version":"v0.15.0",`, true],
      ["duplicate ignored member", `{"root":"one","root":"two",`, true],
    ];
    it.each(prefixes)("%s", async (_name, prefix, wantErr) => {
      const [data, ref] = await manifestBytes(validSpec());
      const changed = enc(prefix + dec(data).slice(1));
      const pinned: RuntimeReference = { ...ref, digest: toHex(await sha256(changed)) };
      if (wantErr) {
        await rejects(parseManifest(changed, pinned), "parsing runtime manifest");
      } else {
        expect(await parseManifest(changed, pinned)).toEqual(validManifest());
        await rejects(parseManifest(changed, ref), "digest pin");
      }
    });
  });

  describe("TestConfigRuntimePin", () => {
    const digest = "ab".repeat(32);
    const accepted: [string, string][] = [
      ["0.15.0", "v0.15.0"],
      ["v0.15.0", "v0.15.0"],
      ["0.15.0-rc.1", "v0.15.0-rc.1"],
      ["0.15.0+gpu", "v0.15.0+gpu"],
      ["v0.15.0+gpu", "v0.15.0+gpu"],
      ["0.15.0-rc.1+gpu", "v0.15.0-rc.1+gpu"],
      ["0.15.0+mini", "v0.15.0+mini"],
      ["0.15.0+containers.initrd-1", "v0.15.0+containers.initrd-1"],
      ["0.15.0+GPU", "v0.15.0+GPU"],
    ];
    it.each(accepted)("accepts %s as %s", (version, tag) => {
      const config = enc(`cvm-version: ${version}@sha256:${digest}\ncontainers: []\n`);
      expect(configRuntime(config)).toEqual({ repo: RUNTIME_REPO, tag, digest });
    });

    const good = `cvm-version: 0.15.0@sha256:${digest}\n`;
    const rejected: [string, string][] = [
      ["unpinned", "cvm-version: 0.15.0\n"],
      ["duplicate", good + good],
      ["two documents", good + "---\n" + good],
      ["bad digest", good.replaceAll(digest, digest.toUpperCase())],
      ["path metadata", good.replaceAll("0.15.0", "0.15.0+mini/other")],
      ["partial version", good.replaceAll("0.15.0", "0.15+gpu")],
      ["empty metadata", good.replaceAll("0.15.0", "0.15.0+")],
      ["double metadata", good.replaceAll("0.15.0", "0.15.0+gpu+gpu")],
      ["short digest", good.replaceAll(digest, digest.slice(0, -2))],
      ["extra digest", good.replaceAll(digest, `${digest}@sha256:${digest}`)],
      ["missing version", "containers: []\n"],
    ];
    it.each(rejected)("%s", (_name, config) => {
      expect(() => configRuntime(enc(config))).toThrow();
    });
  });

  it("TestRuntimeManifestsHaveIndependentPins", async () => {
    const [cpuData, cpuRef] = await manifestBytes(validSpec());
    const gpu = validSpec();
    gpu.version += "+gpu";
    gpu.igvm!.snp_launch!.measurement = "ef".repeat(MEASUREMENT_SIZE);
    gpu.igvm!.tdx_launch!.mrtd = "12".repeat(MEASUREMENT_SIZE);
    const [gpuData, gpuRefPinned] = await manifestBytes(gpu);
    const gpuRef: RuntimeReference = { ...gpuRefPinned, tag: gpu.version };
    const parsed = await parseManifest(gpuData, gpuRef);
    expect(parsed).toEqual({
      version: "v0.15.0+gpu",
      measurements: {
        formatVersion: 1n,
        snpLaunch: { measurement: "ef".repeat(MEASUREMENT_SIZE) },
        tdxLaunch: { mrtd: "12".repeat(MEASUREMENT_SIZE), rtmr0: zeroRegister, rtmr1: zeroRegister, rtmr2: zeroRegister, rtmr3: zeroRegister },
      },
    });
    expect(cpuRef.digest).not.toBe(gpuRef.digest);
    await rejects(parseManifest(cpuData, gpuRef), "digest pin");
    await rejects(parseManifest(gpuData, cpuRef), "digest pin");
    await rejects(parseManifest(gpuData, { ...gpuRef, tag: cpuRef.tag }), "version");
  });
});

// ---------------------------------------------------------------- json v2 decode semantics

/**
 * DecodeManifest uses plain json.Unmarshal (no RejectUnknownMembers), so
 * unknown members are ignored at every depth, while jsontext still rejects
 * duplicate names at every depth, including among ignored members. Go's
 * error text is in the comments where TS wording differs.
 */
describe("runtime.DecodeManifest json v2 semantics (confirmed against Go)", () => {
  const base = manifestJson(validSpec());

  it("baseline", () => {
    expect(decodeManifest(enc(base))).toEqual(validManifest());
  });

  describe("unknown members are ignored", () => {
    it("at the top level", () => {
      expect(decodeManifest(enc(`{"root":"x",` + base.slice(1)))).toEqual(validManifest());
    });
    it("inside igvm", () => {
      const text = base.replace(`"format_version":1`, `"format_version":1,"extra":1`);
      expect(decodeManifest(enc(text))).toEqual(validManifest());
    });
    it("inside tdx_launch", () => {
      const text = base.replace(`"mrtd":`, `"extra":1,"mrtd":`);
      expect(decodeManifest(enc(text))).toEqual(validManifest());
    });
  });

  describe("duplicate members reject", () => {
    // Go: `jsontext: duplicate object member name "root"`.
    it("ignored member at the top level", () => {
      expect(() => decodeManifest(enc(`{"root":"one","root":"two",` + base.slice(1)))).toThrow(
        /^parsing runtime manifest: .*duplicate object member name "root"/,
      );
    });
    it("known member at the top level", () => {
      expect(() => decodeManifest(enc(`{"version":"v0.15.0",` + base.slice(1)))).toThrow(
        /^parsing runtime manifest: .*duplicate object member name "version"/,
      );
    });
    // Go: `jsontext: duplicate object member name "mrtd" within "/igvm/tdx_launch"`.
    it("inside tdx_launch", () => {
      const text = base.replace(`"mrtd":`, `"mrtd":"x","mrtd":`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .*duplicate object member name "mrtd"/);
    });
  });

  describe("format_version (Go int)", () => {
    // Go: "unable to unmarshal JSON number 1.0 into Go int within "/igvm/format_version": invalid syntax".
    it.each([["1.0"], ["1e0"]])("rejects %s", (lit) => {
      const text = base.replace(`"format_version":1`, `"format_version":${lit}`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .* is not an integer/);
    });
    // Go: "unable to unmarshal JSON string into Go int within "/igvm/format_version"".
    it('rejects "1"', () => {
      const text = base.replace(`"format_version":1`, `"format_version":"1"`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .*JSON string into Go number/);
    });
    // Go: null leaves the zero value 0, which is not FormatVersion.
    it("rejects null as 0", () => {
      const text = base.replace(`"format_version":1`, `"format_version":null`);
      expect(() => decodeManifest(enc(text))).toThrow("runtime manifest format is unsupported");
    });
  });

  describe("igvm", () => {
    it("rejects null", () => {
      expect(() => decodeManifest(enc(`{"version":"v0.15.0","igvm":null}`))).toThrow("runtime manifest format is unsupported");
    });
    it("rejects absent", () => {
      expect(() => decodeManifest(enc(`{"version":"v0.15.0"}`))).toThrow("runtime manifest format is unsupported");
    });
  });

  describe("version", () => {
    // Go: null leaves "", which is not a valid semver.
    it("rejects null", () => {
      const text = base.replace(`"version":"v0.15.0"`, `"version":null`);
      expect(() => decodeManifest(enc(text))).toThrow("runtime manifest version must be a full semantic version");
    });
    // Go: "unable to unmarshal JSON number into Go string within "/version"".
    it("rejects a number", () => {
      const text = base.replace(`"version":"v0.15.0"`, `"version":1`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .*JSON number into Go string/);
    });
    it.each([["0.15.0"], ["v0.15"]])("rejects %s as not a full semver", (v) => {
      const text = base.replace(`"version":"v0.15.0"`, `"version":${JSON.stringify(v)}`);
      expect(() => decodeManifest(enc(text))).toThrow("runtime manifest version must be a full semantic version");
    });
  });

  describe("framing", () => {
    // Go: trailing whitespace is fine for the decoder (the digest pin catches it in ParseManifest).
    it("accepts a trailing newline", () => {
      expect(decodeManifest(enc(base + "\n"))).toEqual(validManifest());
    });
    // Go: "jsontext: invalid character '{' after top-level value".
    it("rejects a trailing value", () => {
      expect(() => decodeManifest(enc(base + "{}"))).toThrow(/^parsing runtime manifest: /);
    });
    it("rejects empty input by size", () => {
      expect(() => decodeManifest(new Uint8Array(0))).toThrow("runtime manifest size is outside allowed bounds");
    });
    // Go: "unable to unmarshal JSON array into Go runtime.Manifest".
    it("rejects an array", () => {
      expect(() => decodeManifest(enc("[]"))).toThrow(/^parsing runtime manifest: cannot unmarshal JSON array into runtime manifest/);
    });
  });
});

// ---------------------------------------------------------------- yaml.v3 decode semantics

/**
 * ConfigRuntime decodes with yaml.v3 into struct{ Version string
 * "cvm-version" }: exactly one document, a mapping; any scalar value reads as
 * its text; null reads as "". Go's error text is in the comments where TS
 * wording differs.
 */
describe("runtime.ConfigRuntime yaml semantics (confirmed against Go)", () => {
  const digest = "ab".repeat(32);
  const good = `cvm-version: 0.15.0@sha256:${digest}\n`;
  const want: RuntimeReference = { repo: RUNTIME_REPO, tag: "v0.15.0", digest };

  it("baseline", () => {
    expect(configRuntime(enc(good))).toEqual(want);
  });

  describe("rejects", () => {
    // Go: `yaml: unmarshal errors: line 2: mapping key "cvm-version" already defined at line 1`.
    it("duplicate cvm-version keys", () => {
      expect(() => configRuntime(enc(good + good))).toThrow(/^parsing config runtime pin: /);
    });
    // Go: duplicate keys reject even when the key is not one being decoded.
    it("duplicate other keys", () => {
      expect(() => configRuntime(enc("containers: []\ncontainers: []\n" + good))).toThrow(/^parsing config runtime pin: /);
    });
    it("two documents", () => {
      expect(() => configRuntime(enc(good + "---\n" + good))).toThrow("config must contain exactly one YAML document");
    });
    // Go: the second document decodes as an empty node, not io.EOF.
    it("two documents, the second empty", () => {
      expect(() => configRuntime(enc(good + "---\n"))).toThrow("config must contain exactly one YAML document");
    });
    // Go: "yaml: unmarshal errors: line 1: cannot unmarshal !!seq into struct {...}".
    it("a sequence root", () => {
      expect(() => configRuntime(enc("- " + good))).toThrow("parsing config runtime pin: config is not a mapping");
    });
    // Go: "cannot unmarshal !!str `just a ...` into struct {...}".
    it("a scalar root", () => {
      expect(() => configRuntime(enc("just a string\n"))).toThrow("parsing config runtime pin: config is not a mapping");
    });
    // Go: "parsing config runtime pin: EOF".
    it("an empty file", () => {
      expect(() => configRuntime(new Uint8Array(0))).toThrow("parsing config runtime pin: EOF");
    });
    // Go: "parsing config runtime pin: EOF" (a comment is not a document). The
    // yaml package yields one empty document instead, so TS rejects the empty
    // cvm-version; the outcome is the same.
    it("a comments-only file", () => {
      expect(() => configRuntime(enc("# just a comment\n"))).toThrow();
    });
    // Go: null decodes as "", so the pin is missing.
    it.each([["cvm-version:\n"], ["cvm-version: null\n"], ["cvm-version: ~\n"]])("%j as unpinned", (config) => {
      expect(() => configRuntime(enc(config))).toThrow("cvm-version must pin a runtime manifest SHA-256 digest");
    });
    // Go: yaml.v3 reads any scalar into a string as its text, then the pin is missing.
    it.each([["cvm-version: 0.15\n"], ["cvm-version: 1\n"], ["cvm-version: true\n"]])("%j as the unpinned text", (config) => {
      expect(() => configRuntime(enc(config))).toThrow("cvm-version must pin a runtime manifest SHA-256 digest");
    });
    // Go: "cannot unmarshal !!seq into string" / "cannot unmarshal !!map into string".
    it.each([["cvm-version: [a]\n"], ["cvm-version: {a: b}\n"]])("%j as a non-scalar", (config) => {
      expect(() => configRuntime(enc(config))).toThrow("parsing config runtime pin: cvm-version must be a scalar");
    });
    // Go: "runtime tag must be a full semantic version" (the text "15" becomes tag "v15").
    it("an int-like version", () => {
      expect(() => configRuntime(enc(`cvm-version: 15@sha256:${digest}\n`))).toThrow("runtime tag must be a full semantic version");
    });
    // Go: only the top-level key is read.
    it("a nested cvm-version", () => {
      expect(() => configRuntime(enc(`a:\n  cvm-version: 0.15.0@sha256:${digest}\n`))).toThrow(
        "cvm-version must pin a runtime manifest SHA-256 digest",
      );
    });
    // Go: "yaml: line 1: did not find expected node content".
    it("invalid YAML", () => {
      expect(() => configRuntime(enc("cvm-version: [\n"))).toThrow(/^parsing config runtime pin: /);
    });
    // Go: "yaml: found character that cannot start any token".
    it("a tab-indented line", () => {
      expect(() => configRuntime(enc("\tcvm-version: x\n"))).toThrow(/^parsing config runtime pin: /);
    });
    // Go: "yaml: invalid leading UTF-8 octet".
    it("invalid UTF-8", () => {
      expect(() => configRuntime(new Uint8Array([...enc("cvm-version: "), 0xff, 0x0a]))).toThrow(/^parsing config runtime pin: /);
    });
  });

  describe("accepts", () => {
    it.each([
      ["a double-quoted value", `cvm-version: "0.15.0@sha256:${digest}"\n`],
      ["a single-quoted value", `cvm-version: '0.15.0@sha256:${digest}'\n`],
      ["a folded block scalar", `cvm-version: >-\n  0.15.0@sha256:${digest}\n`],
      ["an explicit document start", "---\n" + good],
      ["an explicit document end", good + "...\n"],
      ["document start and end", "---\n" + good + "...\n"],
      ["a leading comment", "# c\n" + good],
      ["a key with a trailing space", `cvm-version : 0.15.0@sha256:${digest}\n`],
      ["CRLF line endings", good.replaceAll("\n", "\r\n")],
      ["a byte-order mark", "\ufeff" + good],
      ["an alias to an anchored scalar", `a: &x 0.15.0@sha256:${digest}\ncvm-version: *x\n`],
    ])("%s", (_name, config) => {
      expect(configRuntime(enc(config))).toEqual(want);
    });
  });
});
