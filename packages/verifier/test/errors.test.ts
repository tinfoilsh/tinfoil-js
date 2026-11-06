/** The error types: the layer names, and how a rejection carries its layer. */
import { describe, expect, expectTypeOf, it } from "vitest";
import { VerificationError, type KnownLayer, type Layer } from "../src/errors.js";

/**
 * How a caller handles a layer: the names it knows, and a default for one a
 * later version adds. An open union doesn't narrow to a literal on equality,
 * so the known cases are listed and anything else falls through.
 */
function classify(layer: Layer): "known" | "unknown" {
  switch (layer) {
    case "envelope":
    case "provenance":
    case "quote":
    case "policy":
      return "known";
    default:
      return "unknown";
  }
}

describe("Layer", () => {
  it("accepts a layer a later version may add, and keeps the known names as distinct members", () => {
    // Open: any string is a layer, so a caller compiles against the names it knows.
    const later: Layer = "a-later-layer";
    expectTypeOf(later).toExtend<Layer>();
    expectTypeOf<KnownLayer>().toExtend<Layer>();
    expectTypeOf<Layer>().not.toExtend<KnownLayer>();
    expectTypeOf<number>().not.toExtend<Layer>();
    // The known names stay members of the union rather than dissolving into `string`, so they are suggested and selectable.
    expectTypeOf<Extract<Layer, KnownLayer>>().toEqualTypeOf<KnownLayer>();
    expectTypeOf<Extract<Layer, "quote">>().toEqualTypeOf<"quote">();
    expectTypeOf<Exclude<Layer, KnownLayer>>().toEqualTypeOf<string & {}>();
    expect(classify("quote")).toBe("known");
    expect(classify(later)).toBe("unknown");
    const rejected = new VerificationError(later, "rejected");
    expect(rejected.layer).toBe("a-later-layer");
    expect(rejected.message).toBe("verification error: a-later-layer: rejected");
  });
});
