/**
 * Tests for the policy artifact: parsing and validation (policy.parse), policy
 * lookup, platform-measurement resolution, and the per-platform policy
 * validators (sev, tdx, shape).
 *
 * Inputs are JSON text: either a hand-written object (platform-measurement
 * cases) or the fixture decoded with JSON.parse, mutated, and re-encoded.
 * Counts and 64-bit values are bigint, uint8/uint32 fields are number, absent
 * members are undefined, and object maps are Maps.
 *
 * The final describe covers decode-level behaviour: numeric ranges, unknown
 * and duplicate members, null members and framing, each on a single mutation
 * of the fixture.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ARTIFACT_FORMAT,
  ARTIFACT_FORMAT_V2,
  parse,
  PLATFORM_SEV_SNP,
  PLATFORM_TDX,
  policyFor,
  resolvePlatformMeasurement,
  type Artifact,
  type PlatformMeasurement,
  type Policy,
} from "../../src/v3/internal/policy/artifact.js";
import { validateSevSnpPolicy, type SevSnpPolicy, type Tcb } from "../../src/v3/internal/policy/sev.js";
import { satisfies, type Shape } from "../../src/v3/internal/policy/shape.js";
import { validateTdxPolicy, type TdxPolicy } from "../../src/v3/internal/policy/tdx.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

// Real production identifiers (public by design in the endorsement artifact).
const box2TurinID =
  "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const inf7PPID = "3b064a0f58d5dd3688780aeb40e0b5d2";

const fixtureText = readFileSync(new URL("./fixtures/platform-endorsements.json", import.meta.url), "utf8");

function loadFixture(): Artifact {
  return parse(enc(fixtureText));
}

// ---------------------------------------------------------------- JSON rendering helpers

type Tree = Record<string, unknown>;

/** The fixture as a plain mutable object tree. */
function fixtureTree(): Tree {
  return JSON.parse(fixtureText) as Tree;
}

function get(t: Tree, ...path: string[]): Tree {
  let cur = t;
  for (const p of path) cur = cur[p] as Tree;
  return cur;
}

/** Marks a value to be emitted as a raw JSON literal by `render`. */
const raw = (lit: string): string => `__RAW__:${lit}`;

/** Compact JSON text of a tree, with `raw` markers replaced by their literals. */
function render(t: Tree): string {
  return JSON.stringify(t).replace(/"__RAW__:([^"]*)"/g, "$1");
}

/** Renders the fixture after `mutate`. */
function mutated(mutate: (t: Tree) => void): string {
  const t = fixtureTree();
  mutate(t);
  return render(t);
}

const sevBlock = (t: Tree): Tree => get(t, "policies", "amd-turin-prod", "sev_snp");
const tdxBlock = (t: Tree): Tree => get(t, "policies", "tdx-h200-prod", "tdx");

function thrown(f: () => unknown): Error {
  try {
    f();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected an error");
}

// ---------------------------------------------------------------- policy.parse

describe("policy.parse", () => {
  it("parses the fixture artifact", () => {
    const a = loadFixture();
    expect(a.machines.size).toBe(12);
    expect(a.policies.size).toBe(6);
    expect(a.measurements.size).toBe(16);
  });

  describe("validates platform measurements", () => {
    /** One measurement entry as written in the artifact; a null shape stands for an absent shape. */
    interface MeasurementSpec {
      mrtd: string;
      rtmr0: string;
      shape: { cpus: number; memory_mb: number; gpus?: number; disks: number } | null;
    }
    // A minimal artifact holding only the measurement under test: shape is
    // always written (null when absent), gpus is left out when unset, stack
    // is left out, and the machines and policies maps are empty.
    const artifactJson = (m: MeasurementSpec): string =>
      JSON.stringify({ format: ARTIFACT_FORMAT, measurements: { test: m }, machines: {}, policies: {} });

    const cases: [string, (m: MeasurementSpec) => void, string][] = [
      ["optional GPUs", () => {}, ""],
      ["zero GPUs", (m) => (m.shape!.gpus = 0), ""],
      ["positive GPUs", (m) => (m.shape!.gpus = 1), ""],
      ["missing shape", (m) => (m.shape = null), "shape is required"],
      ["zero CPUs", (m) => (m.shape!.cpus = 0), "must be positive"],
      ["negative CPUs", (m) => (m.shape!.cpus = -1), "must be positive"],
      ["zero memory", (m) => (m.shape!.memory_mb = 0), "must be positive"],
      ["negative memory", (m) => (m.shape!.memory_mb = -1), "must be positive"],
      ["zero disks", (m) => (m.shape!.disks = 0), "must be positive"],
      ["negative disks", (m) => (m.shape!.disks = -1), "must be positive"],
      ["negative GPUs", (m) => (m.shape!.gpus = -1), "gpus must be non-negative"],
      ["missing MRTD", (m) => (m.mrtd = ""), "mrtd"],
      ["short MRTD", (m) => (m.mrtd = "ab".repeat(47)), "mrtd"],
      ["oversized MRTD", (m) => (m.mrtd = "AB".repeat(1 << 19)), "mrtd must be 96 hex chars"],
      ["nonhex MRTD", (m) => (m.mrtd = "z".repeat(96)), "mrtd"],
      ["uppercase MRTD", (m) => (m.mrtd = m.mrtd.toUpperCase()), "mrtd"],
      ["missing RTMR0", (m) => (m.rtmr0 = ""), "rtmr0"],
      ["short RTMR0", (m) => (m.rtmr0 = "ab".repeat(47)), "rtmr0"],
      ["oversized RTMR0", (m) => (m.rtmr0 = "AB".repeat(1 << 19)), "rtmr0 must be 96 hex chars"],
      ["nonhex RTMR0", (m) => (m.rtmr0 = "z".repeat(96)), "rtmr0"],
      ["uppercase RTMR0", (m) => (m.rtmr0 = m.rtmr0.toUpperCase()), "rtmr0"],
    ];
    it.each(cases)("%s", (_name, mutate, want) => {
      const m: MeasurementSpec = { mrtd: "ab".repeat(48), rtmr0: "cd".repeat(48), shape: { cpus: 1, memory_mb: 1, disks: 1 } };
      mutate(m);
      // Even an entry unused by any policy must be well formed.
      const data = enc(artifactJson(m));
      if (want === "") {
        expect(() => parse(data)).not.toThrow();
      } else {
        expect(() => parse(data)).toThrow(want);
      }
    });
  });

  it("fails closed on a malformed artifact", () => {
    const wrongFormat = fixtureText.replace("platform-endorsements/v1", "platform-endorsements/v9");
    expect(() => parse(enc(wrongFormat))).toThrow("unsupported artifact format");

    const danglingRef = fixtureText.replace(`"amd-genoa-prod"`, `"no-such-policy"`);
    expect(() => parse(enc(danglingRef))).toThrow("unknown policy");

    // A negative minimum would let any observed collateral satisfy the floor.
    const negativeMin = fixtureText.replace(
      `"minimum_tcb_evaluation_data_number": 19`,
      `"minimum_tcb_evaluation_data_number": -1`,
    );
    expect(negativeMin).not.toBe(fixtureText);
    expect(() => parse(enc(negativeMin))).toThrow("must not be negative");
  });

  it("looks up a machine's policy", () => {
    const a = loadFixture();

    let found = policyFor(a, box2TurinID, PLATFORM_SEV_SNP);
    expect(found.name).toBe("amd-turin-prod");
    expect(found.policy.sevSnp).toBeDefined();

    found = policyFor(a, inf7PPID, PLATFORM_TDX);
    expect(found.name).toBe("tdx-h200-prod");
    expect(found.policy.tdx).toBeDefined();

    // Platform mismatch: TDX identifier presented as SEV evidence.
    expect(() => policyFor(a, inf7PPID, PLATFORM_SEV_SNP)).toThrow("is for platform");

    // Unknown machine: unconditional rejection.
    expect(() => policyFor(a, "ab".repeat(64), PLATFORM_SEV_SNP)).toThrow("not endorsed");
  });

  it("filters platform measurements by the required shape", () => {
    const shapeA: Shape = { cpus: 8n, memoryMb: 65536n, gpus: 1n, disks: 4n };
    const shapeB: Shape = { cpus: 32n, memoryMb: 524288n, gpus: 2n, disks: 5n };
    const a: Artifact = {
      format: "",
      measurements: new Map<string, PlatformMeasurement>([
        ["one-disk", { mrtd: "aa", rtmr0: "bb", shape: shapeA }],
        ["two-disk", { mrtd: "cc", rtmr0: "dd", shape: shapeB }],
        ["no-gpus", { mrtd: "11", rtmr0: "22", shape: { cpus: 8n, memoryMb: 65536n, disks: 4n } }],
        ["legacy", { mrtd: "ee", rtmr0: "ff" }],
      ]),
      machines: new Map(),
      policies: new Map(),
    };
    const p: TdxPolicy = {
      qeVendorId: "",
      minimumTeeTcbSvn: "",
      mrSeam: "",
      tdAttributes: "",
      xfam: "",
      platformMeasurements: ["one-disk", "two-disk", "no-gpus", "legacy"],
    };

    // The required shape is not optional.
    expect(() => resolvePlatformMeasurement(a, p, undefined, "ee", "ff")).toThrow("required VM shape is missing");

    // The shape filter restricts candidates before the measurement lookup.
    let r = resolvePlatformMeasurement(a, p, shapeA, "aa", "bb");
    expect(r.name).toBe("one-disk");
    expect(r.measurement.shape).toEqual(shapeA);

    // A slug without a GPU count satisfies any required GPU count.
    r = resolvePlatformMeasurement(a, p, shapeA, "11", "22");
    expect(r.name).toBe("no-gpus");

    // A quote from an endorsed but differently-shaped VM must not resolve.
    expect(() => resolvePlatformMeasurement(a, p, shapeA, "cc", "dd")).toThrow("do not match any allowed configuration");

    // Entries without shape metadata are never candidates under a filter.
    expect(() => resolvePlatformMeasurement(a, p, shapeA, "ee", "ff")).toThrow("do not match any allowed configuration");

    // A shape no endorsed entry was measured for reports the shape itself.
    expect(() => resolvePlatformMeasurement(a, p, { cpus: 1n, memoryMb: 0n, disks: 0n }, "aa", "bb")).toThrow(
      "required VM shape",
    );
  });
});

// ---------------------------------------------------------------- policy.parse: v2 artifacts

describe("policy.parse: v2 artifacts without workload measurements", () => {
  describe("a platform policy without workload measurements", () => {
    // The fixture as a v2 artifact: the format is bumped and the measurements
    // map, every SEV host_data and every TDX platform_measurements member are
    // removed from the text.
    const v2Tree = (): Tree => {
      const t = fixtureTree();
      t["format"] = ARTIFACT_FORMAT_V2;
      delete t["measurements"];
      for (const p of Object.values(get(t, "policies"))) {
        const policy = p as Tree;
        if (policy["sev_snp"] !== undefined) delete (policy["sev_snp"] as Tree)["host_data"];
        else delete (policy["tdx"] as Tree)["platform_measurements"];
      }
      return t;
    };
    const data = render(v2Tree());

    /** The value the v2 text should parse to: the fixture with an empty measurements map, empty host_data and no platform_measurements. */
    const expected = (): Artifact => {
      const a = loadFixture();
      const policies = new Map<string, Policy>();
      for (const [name, p] of a.policies) {
        policies.set(
          name,
          p.sevSnp !== undefined
            ? { ...p, sevSnp: { ...p.sevSnp, hostData: "" } }
            : { ...p, tdx: { ...p.tdx!, platformMeasurements: undefined } },
        );
      }
      return { format: ARTIFACT_FORMAT_V2, measurements: new Map(), machines: a.machines, policies };
    };

    it("parses the v2 artifact", () => {
      expect(data).not.toContain(`"measurements"`);
      const parsed = parse(enc(data));
      expect(parsed).toEqual(expected());
    });

    const mutations: [string, (t: Tree) => void][] = [
      // Restore every v1-only policy field from the fixture, so the only v1
      // violation left is the missing measurements map that the TDX
      // policies' platform_measurements refer to.
      [
        "v1 requires workload measurements",
        (t) => {
          t["format"] = ARTIFACT_FORMAT;
          const original = get(fixtureTree(), "policies");
          for (const [name, p] of Object.entries(get(t, "policies"))) {
            const policy = p as Tree;
            const from = original[name] as Tree;
            if (policy["sev_snp"] !== undefined) {
              (policy["sev_snp"] as Tree)["host_data"] = (from["sev_snp"] as Tree)["host_data"];
            } else {
              (policy["tdx"] as Tree)["platform_measurements"] = (from["tdx"] as Tree)["platform_measurements"];
            }
          }
        },
      ],
      [
        "v2 excludes host_data",
        (t) => {
          for (const p of Object.values(get(t, "policies"))) {
            const sev = (p as Tree)["sev_snp"] as Tree | undefined;
            if (sev !== undefined) sev["host_data"] = "00".repeat(32);
          }
        },
      ],
      [
        "v2 excludes platform_measurements",
        (t) => {
          for (const p of Object.values(get(t, "policies"))) {
            const tdx = (p as Tree)["tdx"] as Tree | undefined;
            if (tdx !== undefined) tdx["platform_measurements"] = ["legacy"];
          }
        },
      ],
      // An all-empty measurement entry; a v2 artifact must not carry a measurements map at all.
      ["v2 excludes measurement map", (t) => (t["measurements"] = { legacy: { mrtd: "", rtmr0: "", shape: null } })],
    ];
    it.each(mutations)("%s", (name, mutate) => {
      const changed = JSON.parse(data) as Tree;
      mutate(changed);
      const encoded = render(changed);
      expect(encoded).not.toBe(data);
      expect(() => parse(enc(encoded))).toThrow(
        name === "v1 requires workload measurements" ? /platform_measurements ref .* not in measurements/ : /./,
      );
    });

    it.each([["sev_snp"], ["tdx"]])("rejects config_binding in %s", (block) => {
      const marked = JSON.parse(data) as Tree;
      for (const p of Object.values(get(marked, "policies"))) {
        const fields = (p as Tree)[block] as Tree | undefined;
        if (fields !== undefined) fields["config_binding"] = "sha256";
      }
      expect(() => parse(enc(render(marked)))).toThrow("config_binding");
    });
  });
});

// ---------------------------------------------------------------- validateSevSnpPolicy

describe("validateSevSnpPolicy", () => {
  function validSevSnpPolicy(): SevSnpPolicy {
    const tcb: Tcb = { blSpl: 0, teeSpl: 0, snpSpl: 0, ucodeSpl: 0 };
    return {
      minimumBuild: 0,
      minimumApiVersion: "1.55",
      minimumAbiVersion: "0.31",
      minimumGuestSvn: 0,
      minimumTcb: tcb,
      minimumLaunchTcb: tcb,
      guestPolicy: {
        debug: false,
        smt: false,
        migrateMa: false,
        singleSocket: false,
        cxlAllowed: false,
        memAes256Xts: false,
        raplDis: false,
        ciphertextHidingDram: false,
        pageSwapDisable: false,
      },
      platformInfo: {
        smtEnabled: false,
        tsmeEnabled: false,
        eccEnabled: false,
        raplDisabled: false,
        ciphertextHidingDram: false,
        aliasCheckComplete: false,
        iommuWriteSafe: false,
        tioEnabled: false,
      },
      permitProvisionalFirmware: false,
      vmpl: 0n,
      hostData: "ab".repeat(32),
      imageId: "cd".repeat(16),
      familyId: "ef".repeat(16),
      requireAuthorKey: false,
      requireIdBlock: false,
      minimumLaunchMitigationVector: 0n,
      minimumCurrentMitigationVector: 0n,
    };
  }

  describe("validates the encoded fields", () => {
    const p = validSevSnpPolicy();
    it("accepts the valid policy", () => {
      expect(() => validateSevSnpPolicy(p)).not.toThrow();
    });

    type Mutable = { -readonly [K in keyof SevSnpPolicy]: SevSnpPolicy[K] };
    const cases: [string, (p: Mutable) => void][] = [
      ["malformed api version", (p) => (p.minimumApiVersion = "1.2.3")],
      ["version component overflow", (p) => (p.minimumAbiVersion = "256.0")],
      ["uppercase hex", (p) => (p.hostData = p.hostData.toUpperCase())],
      ["short hex", (p) => (p.imageId = p.imageId.slice(0, -2))],
      ["non-hex", (p) => (p.familyId = "z".repeat(32))],
    ];
    it.each(cases)("%s", (_name, mutate) => {
      const bad: Mutable = { ...p };
      mutate(bad);
      expect(() => validateSevSnpPolicy(bad)).toThrow();
    });
  });
});

// ---------------------------------------------------------------- shape.satisfies

describe("shape.satisfies", () => {
  it("is false when either shape is absent", () => {
    const shape: Shape = { cpus: 4n, memoryMb: 4096n, disks: 3n };
    expect(satisfies(shape, undefined)).toBe(false);
    expect(satisfies(undefined, shape)).toBe(false);
  });
});

// ---------------------------------------------------------------- validateTdxPolicy

describe("validateTdxPolicy", () => {
  function validTdxPolicy(): TdxPolicy {
    return {
      qeVendorId: "ab".repeat(16),
      minimumTeeTcbSvn: "00".repeat(16),
      mrSeam: "cd".repeat(48),
      tdAttributes: "00".repeat(8),
      xfam: "00".repeat(8),
      minimumTcbEvaluationDataNumber: 0n,
      platformMeasurements: ["sample"],
    };
  }

  describe("validates the hex fields", () => {
    const p = validTdxPolicy();
    it("accepts the valid policy", () => {
      expect(() => validateTdxPolicy(p)).not.toThrow();
    });

    type Mutable = { -readonly [K in keyof TdxPolicy]: TdxPolicy[K] };
    const cases: [string, (p: Mutable) => void][] = [
      ["uppercase", (p) => (p.qeVendorId = p.qeVendorId.toUpperCase())],
      ["odd length", (p) => (p.mrSeam = p.mrSeam.slice(0, -1))],
      ["non-hex", (p) => (p.xfam = "z".repeat(16))],
    ];
    it.each(cases)("%s", (_name, mutate) => {
      const bad: Mutable = { ...p };
      mutate(bad);
      expect(() => validateTdxPolicy(bad)).toThrow();
    });
  });
});

// ---------------------------------------------------------------- decode semantics

/**
 * Decode-level behaviour of policy.parse: integer ranges and syntax, unknown
 * and duplicate members, null members, and framing. Each case applies one
 * mutation to the fixture and asserts the outcome and the error message.
 */
describe("policy.parse: decode semantics", () => {
  it("baseline: the re-rendered fixture parses", () => {
    expect(() => parse(enc(mutated(() => {})))).not.toThrow();
  });

  describe("uint8 minimum_build", () => {
    it("rejects 256 (overflow)", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = raw("256")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*256 overflows uint8/);
    });
    it("rejects -1 (negative)", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = raw("-1")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*JSON number -1 into uint8/);
    });
    // Any leading '-' is rejected for an unsigned field, even on zero.
    it("rejects -0 (signed zero)", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = raw("-0")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*JSON number -0 into uint8/);
    });
    it("rejects 1.0 (fraction)", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = raw("1.0")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*1\.0 is not an integer/);
    });
    it("rejects 1e0 (exponent)", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = raw("1e0")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*1e0 is not an integer/);
    });
    // A JSON string is rejected for a numeric field; the error names the expected kind and the member path.
    it("rejects a string", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = "0"));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*JSON string into number within "\/minimum_build"/);
    });
    it("accepts 0", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = raw("0")));
      expect(() => parse(enc(data))).not.toThrow();
    });
    // null reads as absent, and the field is required.
    it("rejects null as absent", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_build"] = null));
      expect(() => parse(enc(data))).toThrow(`policy "amd-turin-prod": minimum_build is required`);
    });
  });

  describe("uint64 minimum_launch_mitigation_vector", () => {
    it("accepts 18446744073709551615 (max uint64)", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_launch_mitigation_vector"] = raw("18446744073709551615")));
      const a = parse(enc(data));
      expect(a.policies.get("amd-turin-prod")!.sevSnp!.minimumLaunchMitigationVector).toBe(18446744073709551615n);
    });
    it("rejects 18446744073709551616 (overflow)", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_launch_mitigation_vector"] = raw("18446744073709551616")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*18446744073709551616 overflows uint64/);
    });
  });

  it("rejects uint32 minimum_guest_svn 4294967296 (overflow)", () => {
    const data = mutated((t) => (sevBlock(t)["minimum_guest_svn"] = raw("4294967296")));
    expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*4294967296 overflows uint32/);
  });

  describe("int cpus", () => {
    it("rejects 1.5", () => {
      const data = mutated((t) => (get(t, "measurements", "mini_0d", "shape")["cpus"] = raw("1.5")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*1\.5 is not an integer/);
    });
    it("rejects 9223372036854775808 (int64 overflow)", () => {
      const data = mutated((t) => (get(t, "measurements", "mini_0d", "shape")["cpus"] = raw("9223372036854775808")));
      expect(() => parse(enc(data))).toThrow(/parsing policy artifact: .*9223372036854775808 overflows int64/);
    });
  });

  describe("vmpl", () => {
    it.each([["4"], ["-1"]])("rejects %s after decoding", (lit) => {
      const data = mutated((t) => (sevBlock(t)["vmpl"] = raw(lit)));
      expect(() => parse(enc(data))).toThrow(`policy "amd-turin-prod": vmpl must be between 0 and 3`);
    });
    it("accepts 3", () => {
      const data = mutated((t) => (sevBlock(t)["vmpl"] = raw("3")));
      expect(parse(enc(data)).policies.get("amd-turin-prod")!.sevSnp!.vmpl).toBe(3n);
    });
  });

  describe("unknown members", () => {
    it("rejects inside guest_policy", () => {
      const data = mutated((t) => (get(sevBlock(t), "guest_policy")["extra"] = true));
      expect(() => parse(enc(data))).toThrow(`unknown object member name "extra"`);
    });
    it("rejects inside minimum_tcb", () => {
      const data = mutated((t) => (get(sevBlock(t), "minimum_tcb")["extra"] = raw("0")));
      expect(() => parse(enc(data))).toThrow(`unknown object member name "extra"`);
    });
    it("rejects inside shape", () => {
      const data = mutated((t) => (get(t, "measurements", "mini_0d", "shape")["extra"] = raw("0")));
      expect(() => parse(enc(data))).toThrow(`unknown object member name "extra"`);
    });
    it("rejects at the top level", () => {
      const data = mutated((t) => (t["extra"] = raw("0")));
      expect(() => parse(enc(data))).toThrow(`unknown object member name "extra"`);
    });
  });

  describe("null members", () => {
    // A null shape reads as absent, and the shape is required.
    it("rejects null shape", () => {
      const data = mutated((t) => (get(t, "measurements", "mini_0d")["shape"] = null));
      expect(() => parse(enc(data))).toThrow(`measurement "mini_0d": shape is required`);
    });
    // stack is informational; a null one reads as absent.
    it("accepts null stack", () => {
      const data = mutated((t) => (get(t, "measurements", "mini_0d")["stack"] = null));
      expect(parse(enc(data)).measurements.get("mini_0d")!.stack).toBeUndefined();
    });
    it("rejects null sev_snp", () => {
      const data = mutated((t) => (get(t, "policies", "amd-turin-prod")["sev_snp"] = null));
      expect(() => parse(enc(data))).toThrow(`policy "amd-turin-prod": platform sev-snp requires exactly the sev_snp block`);
    });
    it("rejects null tdx", () => {
      const data = mutated((t) => (get(t, "policies", "tdx-h200-prod")["tdx"] = null));
      expect(() => parse(enc(data))).toThrow(`policy "tdx-h200-prod": platform tdx requires exactly the tdx block`);
    });
    // A null map reads as empty, so the v1 policies' platform_measurements refs dangle.
    it("rejects null measurements in v1 (dangling refs)", () => {
      const data = mutated((t) => (t["measurements"] = null));
      expect(() => parse(enc(data))).toThrow(/platform_measurements ref ".*" not in measurements/);
    });
    // No machines means nothing to endorse, but the artifact is valid.
    it("accepts null machines", () => {
      const data = mutated((t) => (t["machines"] = null));
      expect(parse(enc(data)).machines.size).toBe(0);
    });
    // With no policies, every machine names an unknown policy.
    it("rejects null policies while machines remain", () => {
      const data = mutated((t) => (t["policies"] = null));
      expect(() => parse(enc(data))).toThrow(/^machine [0-9a-f]{16}\.\.\.: unknown policy "/);
    });
    it("accepts null policies and machines", () => {
      const data = mutated((t) => {
        t["policies"] = null;
        t["machines"] = null;
      });
      const a = parse(enc(data));
      expect(a.policies.size).toBe(0);
      expect(a.machines.size).toBe(0);
      expect(a.measurements.size).toBe(16);
    });
    it("accepts null policies, machines and measurements", () => {
      const data = mutated((t) => {
        t["policies"] = null;
        t["machines"] = null;
        t["measurements"] = null;
      });
      const a = parse(enc(data));
      expect(a.policies.size + a.machines.size + a.measurements.size).toBe(0);
    });
    // A null guest_policy reads as the policy with every bit false.
    it("accepts null guest_policy as the all-false policy", () => {
      const data = mutated((t) => (sevBlock(t)["guest_policy"] = null));
      expect(parse(enc(data)).policies.get("amd-turin-prod")!.sevSnp!.guestPolicy.smt).toBe(false);
    });
    // A null minimum_tcb reads as a TCB with no fields set, and each field is required.
    it("rejects null minimum_tcb as the empty TCB", () => {
      const data = mutated((t) => (sevBlock(t)["minimum_tcb"] = null));
      expect(() => parse(enc(data))).toThrow(`policy "amd-turin-prod": minimum_tcb: bl_spl is required`);
    });
    // A null list reads as empty, which v1 forbids.
    it("rejects null platform_measurements in v1", () => {
      const data = mutated((t) => (tdxBlock(t)["platform_measurements"] = null));
      expect(() => parse(enc(data))).toThrow(`policy "tdx-h200-prod": platform_measurements are required in v1 and excluded in v2`);
    });
    // A null string reads as "", which names no policy.
    it("rejects a null machine policy name", () => {
      const data = mutated((t) => (get(t, "machines")[inf7PPID] = null));
      expect(() => parse(enc(data))).toThrow(`machine 3b064a0f58d5dd36...: unknown policy ""`);
    });
  });

  it("rejects a string where shape is expected", () => {
    const data = mutated((t) => (get(t, "measurements", "mini_0d")["shape"] = "x"));
    expect(() => parse(enc(data))).toThrow(/parsing policy artifact: cannot unmarshal JSON string into shape/);
  });

  describe("duplicate member names inside nested blocks", () => {
    it("rejects inside guest_policy", () => {
      const data = mutated(() => {}).replace(`"debug":false`, `"debug":false,"debug":false`);
      expect(() => parse(enc(data))).toThrow(`duplicate object member name "debug"`);
    });
    it("rejects inside a TCB block", () => {
      const data = mutated(() => {}).replace(`"bl_spl":`, `"bl_spl":0,"bl_spl":`);
      expect(() => parse(enc(data))).toThrow(`duplicate object member name "bl_spl"`);
    });
    it("rejects inside shape", () => {
      const data = mutated(() => {}).replace(`"cpus":`, `"cpus":1,"cpus":`);
      expect(() => parse(enc(data))).toThrow(`duplicate object member name "cpus"`);
    });
  });

  it("rejects trailing data", () => {
    expect(() => parse(enc(mutated(() => {}) + "\n{}"))).toThrow(/^parsing policy artifact: /);
  });

  it("rejects empty input", () => {
    expect(() => parse(enc(""))).toThrow(/^parsing policy artifact: /);
  });

  it("wraps decode errors with the parsing prefix", () => {
    const err = thrown(() => parse(enc(mutated((t) => (t["extra"] = raw("0"))))));
    expect(err.message.startsWith("parsing policy artifact: ")).toBe(true);
  });
});
