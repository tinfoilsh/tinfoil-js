// C1: uint64/int64 policy integers must keep full precision. A JS number is
// exact only up to 2^53, so the strict decoder carries 64-bit fields as
// bigints. This guards the sole cross-SDK ACCEPT divergence: an SEV-SNP
// mitigation-vector floor above 2^53 (uint64) must compare bit-exact, never
// rounded, against the report.

import { describe, expect, it } from "vitest";
import {
  field,
  int64Schema,
  intSchema,
  optStructOf,
  uintSchema,
  unmarshal,
} from "../src/v3/strictjson.js";

// Mirror the policy.ts sev_snp / tdx integer members under test.
const policySchema = optStructOf({
  minimum_launch_mitigation_vector: field("launch", uintSchema(64, true)),
  minimum_current_mitigation_vector: field("current", uintSchema(64, true)),
  minimum_tcb_evaluation_data_number: field("tcb", int64Schema(true)),
  vmpl: field("vmpl", intSchema(true)),
});

interface Decoded {
  launch?: bigint;
  current?: bigint;
  tcb?: bigint;
  vmpl?: number;
}

describe("strict JSON 64-bit integers keep full precision (C1)", () => {
  it("decodes uint64 above 2^53 as an exact bigint (no rounding)", () => {
    // 2^53 + 1 is the first integer a JS number cannot represent.
    const above = (1n << 53n) + 1n;
    const max = (1n << 64n) - 1n; // 0xffffffffffffffff
    const json = `{"minimum_launch_mitigation_vector":${above},"minimum_current_mitigation_vector":${max}}`;

    const d = unmarshal(json, policySchema) as Decoded;
    expect(typeof d.launch).toBe("bigint");
    expect(typeof d.current).toBe("bigint");
    expect(d.launch).toBe(above);
    expect(d.current).toBe(max);

    // Sanity: narrowing to a number would have collapsed distinct values.
    expect(Number(above)).toBe(Number(1n << 53n));
    expect(d.launch).not.toBe(1n << 53n);
  });

  it("keeps int64 (tcb_evaluation_data_number) exact while vmpl stays a number", () => {
    const bigTcb = (1n << 62n) + 7n;
    const json = `{"minimum_tcb_evaluation_data_number":${bigTcb},"vmpl":3}`;
    const d = unmarshal(json, policySchema) as Decoded;
    expect(typeof d.tcb).toBe("bigint");
    expect(d.tcb).toBe(bigTcb);
    // Fields that never exceed the safe range remain plain numbers, so
    // strict-equality consumers (e.g. `opts.vmpl !== report.vmpl`) keep
    // comparing number-to-number.
    expect(typeof d.vmpl).toBe("number");
    expect(d.vmpl).toBe(3);
  });

  it("mitigation-vector superset semantics hold bit-exact above 2^53", () => {
    // Reproduce validateMitigationVectors' rule: (report & min) === min.
    const min = (1n << 63n) | 1n; // a bit above 2^53 and the low bit
    const d = unmarshal(
      `{"minimum_launch_mitigation_vector":${min},"minimum_current_mitigation_vector":0}`,
      policySchema,
    ) as Decoded;
    const floor = d.launch!;

    const reportMissingHighBit = 1n; // meets low bit, missing the high bit
    const reportMeetsFloor = (1n << 63n) | 1n | (1n << 5n);
    expect((reportMissingHighBit & floor) === floor).toBe(false); // reject
    expect((reportMeetsFloor & floor) === floor).toBe(true); // accept
  });

  it("still range-checks and rejects an out-of-range uint64", () => {
    const overMax = (1n << 64n).toString(); // 2^64 exceeds the uint64 max
    expect(() =>
      unmarshal(`{"minimum_launch_mitigation_vector":${overMax}}`, policySchema),
    ).toThrow(/out of range/);
  });

  it("absent 64-bit pointer members decode to undefined", () => {
    const d = unmarshal(`{}`, policySchema) as Decoded;
    expect(d.launch).toBeUndefined();
    expect(d.tcb).toBeUndefined();
  });
});
