import { describe, expect, it } from "vitest";
import fixture from "./fixtures/registry-v3/snp-golden.json";
import {
  verifyArtifactApproval,
  verifyConfigApproval,
} from "../src/approvals.js";
import { base64, parseJSON, unbase64, utf8 } from "../src/encoding.js";
import { parseReference } from "../src/references.js";
import boundaries from "./fixtures/approval-v3/boundaries.json";
const input = fixture.input;
const document = parseJSON(unbase64(input.document_b64));
const root = parseJSON(unbase64(input.sigstore_trusted_root_json_b64));
const now = new Date(input.verification_time_unix * 1000);
const maxAge = 7 * 86400000;
const material = (id: string) =>
  document.collateral.find((entry: any) => entry.id === id).data;

describe.each(["config", "runtime", "platform"] as const)(
  "%s pinned approval profile",
  (kind) => {
    const original = material(
      kind === "config" ? "tinfoil-config" : kind + "-freshness",
    ).sigstore_bundle;
    const verify = (bundle: any) =>
      kind === "config"
        ? verifyConfigApproval(
            unbase64(material("tinfoil-config").config_base64),
            bundle,
            parseReference(input.repo),
            input.verifier_options.config_signing_keys_b64.map(unbase64),
            root,
            now,
            maxAge,
          )
        : verifyArtifactApproval(
            bundle,
            { kind, ...fixture.expected[kind] },
            input.verifier_options.freshness_signing_keys_b64.map(unbase64),
            root,
            now,
            maxAge,
          );

    it("accepts the authentic pinned-key approval", async () => {
      const approved = await verify(original);
      const approvalTime =
        approved instanceof Date ? approved : approved.approvalTime;
      expect(approvalTime).toEqual(
        new Date(fixture.expected[kind].approval_time_unix * 1000),
      );
    });
    it("rejects zero signatures", async () => {
      const bundle = structuredClone(original);
      bundle.dsseEnvelope.signatures = [];
      await expect(verify(bundle)).rejects.toThrow("exactly one signature");
    });
    it("rejects wrong DSSE payload and in-toto statement types", async () => {
      const payloadType = structuredClone(original);
      payloadType.dsseEnvelope.payloadType = "application/json";
      await expect(verify(payloadType)).rejects.toThrow("DSSE payload type");
      const statementType = structuredClone(original),
        statement = parseJSON(unbase64(statementType.dsseEnvelope.payload));
      statement._type = "https://in-toto.io/Statement/v0.1";
      statementType.dsseEnvelope.payload = base64(
        utf8(JSON.stringify(statement)),
      );
      await expect(verify(statementType)).rejects.toThrow("statement type");
    });
    it("rejects zero or more than eight receipts", async () => {
      for (const count of [0, 9]) {
        const bundle = structuredClone(original);
        bundle.verificationMaterial.tlogEntries = Array.from(
          { length: count },
          () => structuredClone(original.verificationMaterial.tlogEntries[0]),
        );
        await expect(verify(bundle)).rejects.toThrow("receipt count");
      }
    });
    it("rejects inclusion promises in the proof-only profile", async () => {
      const bundle = structuredClone(original);
      bundle.verificationMaterial.tlogEntries[0].inclusionPromise = {
        signedEntryTimestamp: "AA==",
      };
      await expect(verify(bundle)).rejects.toThrow("Rekor v2 inclusion proofs");
    });
  },
);

describe("authentic approval trust boundaries", () => {
  const verify = (bundle: unknown) =>
    verifyConfigApproval(
      unbase64(boundaries.config),
      bundle,
      parseReference("example/service"),
      [unbase64(boundaries.key)],
      boundaries.root as any,
      new Date(boundaries.now * 1000),
      maxAge,
    );
  it("accepts the maximum eight independent authenticated log receipts", async () => {
    await expect(verify(boundaries.eight)).resolves.toBeDefined();
  });
  it("rejects nine independently authentic log receipts", async () => {
    await expect(verify(boundaries.nine)).rejects.toThrow("receipt count");
  });
  it("rejects a valid TSA signature issued under the wrong timestamp policy", async () => {
    await expect(verify(boundaries.wrongPolicy)).rejects.toThrow(
      "Timestamp policy",
    );
  });
  it("rejects empty and oversized config bytes before accepting an approval", async () => {
    for (const bytes of [new Uint8Array(), new Uint8Array((1 << 20) + 1)])
      await expect(
        verifyConfigApproval(
          bytes,
          boundaries.eight,
          parseReference("example/service"),
          [unbase64(boundaries.key)],
          boundaries.root as any,
          new Date(boundaries.now * 1000),
          maxAge,
        ),
      ).rejects.toThrow("Config size");
  });
  it("rejects oversized statement and bundle encodings", async () => {
    const oversizedStatement = structuredClone(boundaries.eight);
    const statement = parseJSON(
      unbase64(oversizedStatement.dsseEnvelope.payload),
    );
    statement.subject[0].name = "x".repeat(131072);
    oversizedStatement.dsseEnvelope.payload = base64(
      utf8(JSON.stringify(statement)),
    );
    await expect(verify(oversizedStatement)).rejects.toThrow("Approval size");
    const oversizedBundle = {
      ...structuredClone(boundaries.eight),
      extension: "x".repeat(4 * 1024 * 1024),
    };
    await expect(verify(oversizedBundle)).rejects.toThrow("Approval size");
  });
});
