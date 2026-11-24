/**
 * Tests for the runtime manifest (parseManifest / decodeManifest) and the
 * runtime pin read from the config (configRuntime).
 *
 * Manifest inputs are built from a spec object and rendered by `manifestJson`
 * as compact JSON in a fixed member order; a null spec member is written as
 * an explicit JSON null. Integer fields parse as bigint.
 *
 * The trailing describes cover decode-level behaviour: unknown and duplicate
 * members, integer and string typing, null members and framing for the
 * manifest, and the JSON object and member that the config's pin is read from.
 */
import { describe, expect, it } from "vitest";
import { RUNTIME_REPO, type RuntimeReference } from "../src/document/collateral/runtime.js";
import { sha256, toHex } from "../src/internal/bytes.js";
import { configRuntime, MAX_CONFIG_SIZE } from "../src/internal/runtime/config.js";
import { decodeManifest, FORMAT_VERSION, MEASUREMENT_SIZE, parseManifest, type Manifest } from "../src/internal/runtime/manifest.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => new TextDecoder().decode(b);

/** A mutable spec for building manifest JSON (null = an explicit null member). */
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

/** The valid manifest as a JSON-building spec. */
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

/** The valid manifest as its parsed value. */
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

/** Compact manifest text in member order: version, igvm{format_version, snp_launch, tdx_launch}. */
const manifestJson = (m: ManifestSpec): string => JSON.stringify(m);

/** The manifest's JSON bytes and the pin whose digest is theirs. */
async function manifestBytes(m: ManifestSpec): Promise<[Uint8Array, RuntimeReference]> {
  const data = enc(manifestJson(m));
  return [data, { repo: RUNTIME_REPO, tag: "v0.15.0", digest: toHex(await sha256(data)) }];
}

async function rejects(p: Promise<unknown>, want?: string | RegExp): Promise<void> {
  if (want === undefined) await expect(p).rejects.toThrow();
  else await expect(p).rejects.toThrow(want);
}

// ---------------------------------------------------------------- parseManifest and configRuntime

describe("parseManifest and configRuntime", () => {
  describe("requires complete supported measurements", () => {
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

  describe("reads the runtime pin from the config", () => {
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
      const config = enc(`{"containers":[],"cvm-version":"${version}@sha256:${digest}"}`);
      expect(configRuntime(config)).toEqual({ repo: RUNTIME_REPO, tag, digest });
    });

    const pin = `"cvm-version":"0.15.0@sha256:${digest}"`;
    const good = `{${pin}}`;
    const rejected: [string, string][] = [
      ["unpinned", `{"cvm-version":"0.15.0"}`],
      ["duplicate", `{${pin},${pin}}`],
      ["two values", good + good],
      ["bad digest", good.replaceAll(digest, digest.toUpperCase())],
      ["path metadata", good.replaceAll("0.15.0", "0.15.0+mini/other")],
      ["partial version", good.replaceAll("0.15.0", "0.15+gpu")],
      ["empty metadata", good.replaceAll("0.15.0", "0.15.0+")],
      ["double metadata", good.replaceAll("0.15.0", "0.15.0+gpu+gpu")],
      ["short digest", good.replaceAll(digest, digest.slice(0, -2))],
      ["extra digest", good.replaceAll(digest, `${digest}@sha256:${digest}`)],
      ["missing version", `{"containers":[]}`],
    ];
    it.each(rejected)("%s", (_name, config) => {
      expect(() => configRuntime(enc(config))).toThrow();
    });
  });

  it("pins each runtime manifest independently", async () => {
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

// ---------------------------------------------------------------- decodeManifest decode semantics

/**
 * decodeManifest ignores unknown members at every depth, but rejects
 * duplicate member names at every depth, including among ignored members.
 */
describe("decodeManifest: decode semantics", () => {
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
    it("inside tdx_launch", () => {
      const text = base.replace(`"mrtd":`, `"mrtd":"x","mrtd":`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .*duplicate object member name "mrtd"/);
    });
  });

  describe("format_version (integer)", () => {
    // An integer field rejects fractional and exponent literals.
    it.each([["1.0"], ["1e0"]])("rejects %s", (lit) => {
      const text = base.replace(`"format_version":1`, `"format_version":${lit}`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .* is not an integer/);
    });
    // A JSON string is rejected for a numeric field.
    it('rejects "1"', () => {
      const text = base.replace(`"format_version":1`, `"format_version":"1"`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .*JSON string into number/);
    });
    // null reads as 0, which is not the supported format version.
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
    // null reads as "", which is not a full semantic version.
    it("rejects null", () => {
      const text = base.replace(`"version":"v0.15.0"`, `"version":null`);
      expect(() => decodeManifest(enc(text))).toThrow("runtime manifest version must be a full semantic version");
    });
    // A JSON number is rejected for a string field.
    it("rejects a number", () => {
      const text = base.replace(`"version":"v0.15.0"`, `"version":1`);
      expect(() => decodeManifest(enc(text))).toThrow(/^parsing runtime manifest: .*JSON number into string/);
    });
    it.each([["0.15.0"], ["v0.15"]])("rejects %s as not a full semver", (v) => {
      const text = base.replace(`"version":"v0.15.0"`, `"version":${JSON.stringify(v)}`);
      expect(() => decodeManifest(enc(text))).toThrow("runtime manifest version must be a full semantic version");
    });
  });

  describe("framing", () => {
    // Trailing whitespace is fine for the decoder; the digest pin in parseManifest catches it.
    it("accepts a trailing newline", () => {
      expect(decodeManifest(enc(base + "\n"))).toEqual(validManifest());
    });
    it("rejects a trailing value", () => {
      expect(() => decodeManifest(enc(base + "{}"))).toThrow(/^parsing runtime manifest: /);
    });
    it("rejects empty input by size", () => {
      expect(() => decodeManifest(new Uint8Array(0))).toThrow("runtime manifest size is outside allowed bounds");
    });
    it("rejects an array", () => {
      expect(() => decodeManifest(enc("[]"))).toThrow(/^parsing runtime manifest: cannot unmarshal JSON array into runtime manifest/);
    });
  });
});

// ---------------------------------------------------------------- configRuntime decode semantics

/**
 * configRuntime reads the top-level cvm-version member of a JSON config: the
 * bytes must strictly parse as one JSON object, and the member must be a
 * string. Neither the version it pins nor the spelling of the JSON decides
 * the outcome, and YAML rejects.
 */
describe("configRuntime: decode semantics", () => {
  const digest = "ab".repeat(32);
  const pin = `"cvm-version":"0.15.0@sha256:${digest}"`;
  const good = `{${pin}}`;
  const want: RuntimeReference = { repo: RUNTIME_REPO, tag: "v0.15.0", digest };
  const yaml = (version: string): string => `cvm-version: ${version}@sha256:${digest}\ncpus: 2\n`;
  const notJsonConfig = "parsing config runtime pin: not a JSON config that states cvm-version; YAML configs are not read";

  it("baseline", () => {
    expect(configRuntime(enc(good))).toEqual(want);
  });

  describe("rejects", () => {
    it.each([
      ["YAML", yaml("0.15.0")],
      ["YAML for a later version", yaml("0.15.5-rc.1")],
      ["flow-style YAML", `{cvm-version: 0.15.0@sha256:${digest}, cpus: 2}`],
      ["duplicate cvm-version members", `{${pin},${pin}}`],
      // Duplicate members reject even when the member is not the one being read.
      ["duplicate other members", `{"containers":[],"containers":[],${pin}}`],
      ["two values", good + good],
      ["an array root", `[${good}]`],
      ["a string root", `"just a string"`],
      ["an empty file", ""],
      ["an object without cvm-version", `{"containers":[]}`],
      // Only the top-level member is read.
      ["a nested cvm-version", `{"a":${good}}`],
      ["a null cvm-version", `{"cvm-version":null}`],
      ["a number cvm-version", `{"cvm-version":1}`],
      ["a boolean cvm-version", `{"cvm-version":true}`],
      ["an array cvm-version", `{"cvm-version":["a"]}`],
      ["an object cvm-version", `{"cvm-version":{"a":"b"}}`],
      ["truncated JSON", good.slice(0, -1)],
      ["a comment", "// c\n" + good],
      ["single-quoted strings", good.replaceAll(`"`, "'")],
      ["a byte-order mark", String.fromCodePoint(0xfeff) + good],
    ])("%s", (_name, config) => {
      expect(() => configRuntime(enc(config))).toThrow(notJsonConfig);
    });
    it("invalid UTF-8", () => {
      const config = new Uint8Array([...enc(`{"cvm-version":"`), 0xff, ...enc(`"}`)]);
      expect(() => configRuntime(config)).toThrow(notJsonConfig);
    });
    it("an empty cvm-version as unpinned", () => {
      expect(() => configRuntime(enc(`{"cvm-version":""}`))).toThrow("cvm-version must pin a runtime manifest SHA-256 digest");
    });
    // The text "15" becomes tag "v15", which is not a full semantic version.
    it("an int-like version", () => {
      expect(() => configRuntime(enc(`{"cvm-version":"15@sha256:${digest}"}`))).toThrow("runtime tag must be a full semantic version");
    });
    // The bytes are not JSON: parsing them would report that instead of the size.
    it("a config over the size limit, without parsing it", () => {
      const config = enc("x".repeat(MAX_CONFIG_SIZE + 1));
      expect(() => configRuntime(config)).toThrow(`parsing config runtime pin: the config is larger than ${MAX_CONFIG_SIZE} bytes`);
    });
  });

  describe("accepts", () => {
    it.each([
      ["whitespace and a trailing newline", `{\n  "cpus": 2,\n  "cvm-version": "0.15.0@sha256:${digest}"\n}\n`],
      ["members in any order", `{"shim":{"upstream-port":8080},${pin},"containers":[]}`],
      ["null in another member", `{"cpus":null,${pin}}`],
      ["a fraction in another member", `{"cpus":2.5,${pin}}`],
      ["a config of the largest size", good.padEnd(MAX_CONFIG_SIZE)],
    ])("%s", (_name, config) => {
      expect(configRuntime(enc(config))).toEqual(want);
    });
    // Guests take a JSON config from 0.15.5-rc.1; the reader takes one for any version.
    it.each([["0.15.4"], ["0.15.5-rc.1"]])("version %s", (version) => {
      expect(configRuntime(enc(good.replace("0.15.0", version)))).toEqual({ ...want, tag: "v" + version });
    });
  });
});
