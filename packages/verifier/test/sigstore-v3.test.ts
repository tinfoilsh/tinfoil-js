import { describe, expect, it } from "vitest";
import fixture from "./fixtures/sigstore-v3/two-observers.json";
import { verifyStatement, type SigstoreRoot } from "../src/sigstore.js";
import { workflowIdentity } from "../src/references.js";
import boundaries from "./fixtures/sigstore-v3/provenance-boundaries.json";
import { authenticateCode } from "../src/provenance.js";
import { parseReference } from "../src/references.js";

describe("authenticated Sigstore observer times", () => {
  const verify = (bundle = fixture.bundle, root: unknown = fixture.root) =>
    verifyStatement(
      bundle,
      workflowIdentity(fixture.repo),
      fixture.digest,
      root as SigstoreRoot,
    );

  it("accepts authenticated receipts with distinct global and shard-local indexes", async () => {
    const result = await verify();
    expect(result.tlogTimes.map((date) => date.getTime())).toEqual([
      fixture.first * 1000,
      fixture.second * 1000,
    ]);
  });

  it("checks CA retirement against every authenticated observer", async () => {
    const root = structuredClone(fixture.root);
    Object.assign(root.certificateAuthorities[0].validFor, {
      end: new Date(fixture.first * 1000).toISOString(),
    });
    const firstOnly = structuredClone(fixture.bundle);
    firstOnly.verificationMaterial.tlogEntries.pop();
    await expect(verify(firstOnly, root)).resolves.toBeDefined();
    await expect(verify(fixture.bundle, root)).rejects.toThrow(
      "certificate chain",
    );
    const reversed = structuredClone(fixture.bundle);
    reversed.verificationMaterial.tlogEntries.reverse();
    await expect(verify(reversed, root)).rejects.toThrow("certificate chain");
  });

  it("does not ignore an invalid later receipt or duplicate receipt", async () => {
    const forged = structuredClone(fixture.bundle);
    forged.verificationMaterial.tlogEntries[1].inclusionPromise.signedEntryTimestamp =
      forged.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp;
    await expect(verify(forged)).rejects.toThrow("signed entry timestamp");
    const duplicate = structuredClone(fixture.bundle);
    duplicate.verificationMaterial.tlogEntries[1] =
      duplicate.verificationMaterial.tlogEntries[0];
    await expect(verify(duplicate)).rejects.toThrow("Duplicate");
  });
});

describe("signed provenance boundary cases", () => {
  it.each(boundaries.cases)("$name", async (fixture) => {
    const result = authenticateCode(
      {
        bundle: fixture.bundle,
        repo: boundaries.repo,
        tag: "v1.0.0",
        digest: boundaries.digest,
      },
      parseReference(boundaries.repo + "@v1.0.0"),
      fixture.root as unknown as SigstoreRoot,
    );
    if (fixture.accepted)
      await expect(result).resolves.toHaveProperty(
        "tdx.rtmr2",
        "33".repeat(48),
      );
    else if (fixture.name.includes("SCT"))
      await expect(result).rejects.toThrow(/SCT/i);
    else if (fixture.name.includes("shape"))
      await expect(result).rejects.toThrow("VM shape");
    else await expect(result).rejects.toThrow();
  });
});
