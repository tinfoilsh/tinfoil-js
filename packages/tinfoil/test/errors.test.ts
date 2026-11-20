/** Finding the SDK error behind an error from the OpenAI library or any other wrapper. */
import { APIConnectionError, APIConnectionTimeoutError, RateLimitError } from "openai";
import { describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError, findTinfoilError, NetworkError } from "../src/errors.js";
import * as root from "../src/index.js";

describe("findTinfoilError", () => {
  it("is exported from the package root", () => {
    expect(root.findTinfoilError).toBe(findTinfoilError);
  });

  it("returns an SDK error itself, or the first one in the cause chain", () => {
    const attestation = new AttestationError("rejected");
    expect(findTinfoilError(attestation)).toBe(attestation);
    expect(findTinfoilError(new APIConnectionError({ cause: attestation }))).toBe(attestation);
    const network = new NetworkError("unreachable");
    expect(findTinfoilError(new APIConnectionTimeoutError({ message: "timed out" }))).toBeUndefined();
    const wrapped = new Error("outer", { cause: new Error("middle", { cause: network }) });
    expect(findTinfoilError(wrapped)).toBe(network);
    // The first SDK error wins, even when it has a cause of its own.
    const configuration = new ConfigurationError("bad", { cause: network });
    expect(findTinfoilError(new Error("outer", { cause: configuration }))).toBe(configuration);
  });

  it("returns undefined for an API error, a value that isn't an error, a cycle or a chain too long to follow", () => {
    expect(findTinfoilError(new RateLimitError(429, undefined, "slow down", new Headers()))).toBeUndefined();
    for (const value of [undefined, null, "attestation error", 7, {}]) expect(findTinfoilError(value)).toBeUndefined();
    const a: { cause?: unknown } = {};
    const b = { cause: a };
    a.cause = b;
    expect(findTinfoilError(a)).toBeUndefined();
    let deep: unknown = new AttestationError("deep");
    for (let i = 0; i < 40; i++) deep = new Error(`level ${i}`, { cause: deep });
    expect(findTinfoilError(deep)).toBeUndefined();
  });
});
