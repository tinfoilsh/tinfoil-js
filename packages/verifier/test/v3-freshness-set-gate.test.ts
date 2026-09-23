// Freshness anti-replay hardening: a transparency-log entry's integratedTime
// anchors freshness only when its inclusion promise (SET) is present, so a
// TSA-only entry (the trusted root carries a TSA) cannot feed an unverified
// timestamp into the freshness window. Mirrors the Go filter to VERIFIED Tlog
// timestamps (verifier/provenance/freshness.go) and the Python fix.

import { describe, expect, it } from "vitest";
import type { WireBundle, WireTLogEntry } from "../src/v3/provenance/bundle-format.js";
import { tlogObserverTimestamps } from "../src/v3/provenance/provenance.js";

function bundle(entries: Array<Partial<WireTLogEntry>>): WireBundle {
  return {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { tlogEntries: entries as WireTLogEntry[] },
  };
}

describe("tlog observer timestamps require an inclusion promise (SET)", () => {
  it("counts an entry whose inclusion promise and integratedTime are present", () => {
    const ts = tlogObserverTimestamps(
      bundle([{ integratedTime: "1700000000", inclusionPromise: { signedEntryTimestamp: "c2ln" } }]),
    );
    expect(ts).toHaveLength(1);
    expect(ts[0].getTime()).toBe(1700000000 * 1000);
  });

  it("ignores an entry that has integratedTime but no inclusion promise", () => {
    // A TSA-only / promise-less entry must NOT contribute a freshness anchor,
    // so a stale document relying on it has no verified timestamp and rejects.
    expect(tlogObserverTimestamps(bundle([{ integratedTime: "1700000000" }]))).toHaveLength(0);
  });

  it("ignores an entry whose inclusion promise carries an empty SET", () => {
    expect(
      tlogObserverTimestamps(
        bundle([{ integratedTime: "1700000000", inclusionPromise: { signedEntryTimestamp: "" } }]),
      ),
    ).toHaveLength(0);
  });

  it("keeps only the SET-bearing entries when several are present", () => {
    const ts = tlogObserverTimestamps(
      bundle([
        { integratedTime: "1700000000" }, // no promise -> dropped
        { integratedTime: "1700000500", inclusionPromise: { signedEntryTimestamp: "c2ln" } },
      ]),
    );
    expect(ts.map((d) => d.getTime())).toEqual([1700000500 * 1000]);
  });
});
