/** The error types: the layer names, how a rejection carries its layer, and `instanceof` across copies of the package. */
import { describe, expect, expectTypeOf, it, vi } from "vitest";
import { UsageError, VerificationError, VerifyError, type KnownLayer, type Layer } from "../src/errors.js";

/** The key the errors carry their brand under, registered globally so every copy of the package shares it. */
const BRAND = Symbol.for("@tinfoilsh/verifier.error");

/** A second, independently evaluated copy of the errors module, as a duplicate install of the package would load. */
async function secondCopy(): Promise<typeof import("../src/errors.js")> {
  vi.resetModules();
  const copy = await import("../src/errors.js");
  expect(copy.UsageError).not.toBe(UsageError);
  return copy;
}

describe("instanceof across copies of the package", () => {
  it("recognizes an error constructed by another copy's class, by its brand", async () => {
    const other = await secondCopy();
    const usage = new other.UsageError("bad pin");
    expect(usage instanceof UsageError).toBe(true);
    expect(usage instanceof VerifyError).toBe(true);
    expect(usage instanceof VerificationError).toBe(false);
    const rejected = new other.VerificationError("bad report", { layer: "quote" });
    expect(rejected instanceof VerificationError).toBe(true);
    expect(rejected instanceof VerifyError).toBe(true);
    expect(rejected instanceof UsageError).toBe(false);
    // And the other way round, since both copies check the same brand.
    expect(new UsageError("x") instanceof other.UsageError).toBe(true);
    expect(new VerificationError("x", { layer: "policy" }) instanceof other.VerifyError).toBe(true);
    // A subclass of the other copy's class matches by prototype only, so this copy's errors are not its instances.
    class OtherSub extends other.UsageError {}
    expect(new UsageError("x") instanceof OtherSub).toBe(false);
    expect(new OtherSub("x") instanceof UsageError).toBe(true);
  });

  it("still matches its own instances and subclasses, and nothing unrelated", () => {
    class Mine extends VerifyError {}
    const mine = new Mine("mine");
    expect(mine instanceof VerifyError).toBe(true);
    expect(mine instanceof UsageError).toBe(false);
    // A subclass inherits the hasInstance check but not the brand match: it matches its own instances only, never its siblings or its base's.
    class MyUsage extends UsageError {}
    class OtherUsage extends UsageError {}
    expect(new MyUsage("x") instanceof MyUsage).toBe(true);
    expect(new MyUsage("x") instanceof UsageError).toBe(true);
    expect(new MyUsage("x") instanceof VerifyError).toBe(true);
    expect(new UsageError("x") instanceof MyUsage).toBe(false);
    expect(new OtherUsage("x") instanceof MyUsage).toBe(false);
    expect(mine instanceof Mine).toBe(true);
    expect(new UsageError("x") instanceof Mine).toBe(false);
    class MyRejection extends VerificationError {}
    expect(new VerificationError("x", { layer: "quote" }) instanceof MyRejection).toBe(false);
    expect(new MyRejection("x", { layer: "quote" }) instanceof VerificationError).toBe(true);
    expect(new UsageError("x") instanceof UsageError).toBe(true);
    expect(new UsageError("x") instanceof VerifyError).toBe(true);
    expect(new UsageError("x") instanceof VerificationError).toBe(false);
    expect(new VerificationError("x", { layer: "quote" }) instanceof UsageError).toBe(false);
    for (const unrelated of [new Error("x"), { name: "UsageError", message: "x" }, Object.assign(new Error("x"), { name: "UsageError" }), null, undefined, "UsageError", 1]) {
      expect(unrelated instanceof VerifyError, String(unrelated)).toBe(false);
      expect(unrelated instanceof UsageError, String(unrelated)).toBe(false);
      expect(unrelated instanceof VerificationError, String(unrelated)).toBe(false);
    }
    // A brand with a value the package never stamps is no brand.
    expect(Object.assign(new Error("x"), { [BRAND]: "Other" }) instanceof VerifyError).toBe(false);
  });

  it("stamps the brand so it doesn't show when the error is serialized or enumerated", () => {
    const usage = new UsageError("x", { cause: "c" });
    expect((usage as unknown as Record<symbol, unknown>)[BRAND]).toBe("UsageError");
    expect(Object.keys(usage)).toEqual(["cause", "name"]);
    expect(Object.getOwnPropertySymbols(usage)).toEqual([BRAND]);
    expect(JSON.parse(JSON.stringify(usage))).toEqual({ cause: "c", name: "UsageError" });
    expect(Object.getOwnPropertyDescriptor(usage, BRAND)).toMatchObject({ enumerable: false, writable: false, configurable: false });
  });
});

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
    const rejected = new VerificationError("rejected", { layer: later });
    expect(rejected.layer).toBe("a-later-layer");
    expect(rejected.message).toBe("verification error: a-later-layer: rejected");
  });
});
