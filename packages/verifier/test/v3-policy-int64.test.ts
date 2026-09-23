// C1 int64 hardening at the policy layer: a TDX minimum_tcb_evaluation_data_number
// above 2^53 must survive policy.parseArtifact as an exact bigint (matching
// Python's exact int), not a rounded JS number. All conformance fixtures keep
// the value <= 2^53, so this precision is invisible to the cross-SDK suite and
// only a dedicated test exercises it.

import { describe, expect, it } from "vitest";

import { parseArtifact, ArtifactFormat } from "../src/v3/policy.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

// A minimal, valid platform-endorsements artifact carrying one TDX policy whose
// tcb floor is injected verbatim (so a bigint literal survives JSON).
function artifactJSON(tcbLiteral: string): string {
  const id = "ab".repeat(16); // 32 lowercase hex chars => valid TDX identifier
  const doc = {
    format: ArtifactFormat,
    measurements: {
      m0: {
        mrtd: "aa".repeat(48),
        rtmr0: "bb".repeat(48),
        shape: { cpus: 2, memory_mb: 1024, gpus: 0, disks: 3 },
        stack: null,
      },
    },
    machines: { [id]: "p0" },
    policies: {
      p0: {
        platform: "tdx",
        sev_snp: null,
        tdx: {
          qe_vendor_id: "00".repeat(16),
          minimum_tee_tcb_svn: "00".repeat(16),
          mr_seam: "00".repeat(48),
          td_attributes: "00".repeat(8),
          xfam: "00".repeat(8),
          minimum_tcb_evaluation_data_number: "__TCB__",
          platform_measurements: ["m0"],
        },
      },
    },
  };
  // Replace the sentinel string with a bare integer literal so a value above
  // 2^53 is not rounded by JSON.stringify (which cannot emit bigint).
  return JSON.stringify(doc).replace('"__TCB__"', tcbLiteral);
}

describe("policy int64 tcb_evaluation_data_number keeps full precision (C1)", () => {
  it("parses a minimum_tcb_evaluation_data_number above 2^53 as an exact bigint", () => {
    const bigTcb = (1n << 60n) + 123n; // 0x1000000000000007b, far above 2^53
    const a = parseArtifact(enc(artifactJSON(bigTcb.toString())));
    const value = a.policies.get("p0")!.tdx!.minimumTCBEvaluationDataNumber as unknown;
    expect(typeof value).toBe("bigint");
    expect(value as bigint).toBe(bigTcb);
    // A JS number would have collapsed this onto 2^60.
    expect(Number(bigTcb)).toBe(Number(1n << 60n));
    expect(value as bigint).not.toBe(1n << 60n);
  });

  it("still accepts a small in-range value", () => {
    const a = parseArtifact(enc(artifactJSON("5")));
    expect(a.policies.get("p0")!.tdx!.minimumTCBEvaluationDataNumber as unknown).toBe(5n);
  });

  it("still rejects a negative tcb_evaluation_data_number", () => {
    expect(() => parseArtifact(enc(artifactJSON("-1")))).toThrowError(/must not be negative/);
  });
});
