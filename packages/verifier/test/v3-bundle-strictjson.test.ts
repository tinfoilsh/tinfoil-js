// D1: parseBundle runs the strict raw-JSON walk over the WHOLE bundle
// document, so a duplicate member anywhere in the envelope rejects (Python +
// protojson do). Previously the strict walk ran only on the DSSE payload and
// the bundle envelope went through a permissive JSON.parse (duplicates
// last-win).

import { describe, expect, it } from "vitest";
import { VerificationError } from "../src/v3/errors.js";
import { parseBundle } from "../src/v3/provenance/bundle-format.js";

const validMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json";
const enc = (s: string) => new TextEncoder().encode(s);

describe("parseBundle strict whole-document JSON (D1)", () => {
  it("accepts a well-formed bundle with a supported media type", () => {
    const b = parseBundle(enc(`{"mediaType":"${validMediaType}"}`));
    expect(b.mediaType).toBe(validMediaType);
  });

  it("rejects a duplicate member in the bundle envelope", () => {
    const json = `{"mediaType":"${validMediaType}","mediaType":"${validMediaType}"}`;
    expect(() => parseBundle(enc(json))).toThrow(VerificationError);
    expect(() => parseBundle(enc(json))).toThrow(/duplicate object member/);
  });

  it("rejects a duplicate member nested inside verificationMaterial", () => {
    const json =
      `{"mediaType":"${validMediaType}",` +
      `"verificationMaterial":{"tlogEntries":[],"tlogEntries":[]}}`;
    expect(() => parseBundle(enc(json))).toThrow(/duplicate object member/);
  });

  it("rejects trailing data after the bundle document", () => {
    expect(() => parseBundle(enc(`{"mediaType":"${validMediaType}"} garbage`))).toThrow(
      /parsing bundle/,
    );
  });
});
