import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { utf8Encode } from "../src/v3/bytes.js";
import { trustedRootJSON } from "../src/v3/embedded/roots.js";
import type { WireBundle } from "../src/v3/provenance/bundle-format.js";
import { authenticateFreshness } from "../src/v3/provenance/freshness.js";
import { authenticateCode, verifyBundleWithIdentity } from "../src/v3/provenance/provenance.js";

const repo = "tinfoilsh/private-attestation-e2e";
const tag = "v1.0.1";
const commit = "69a541884f63ab38ec725f0d7e02e06595b875f0";
const digest = "5ea52b374e0ce8da0367c17a7d954392c07dcf26993bc2bc57fa540b9b858baa";

function fixture(name: string): Uint8Array {
  return readFileSync(new URL(`./fixtures/private-provenance/${name}`, import.meta.url));
}

describe("private GitHub provenance", () => {
  it("verifies the captured certificate, RFC 3161 timestamp and DSSE signature", async () => {
    const code = await authenticateCode(fixture("private-source.json"), repo, tag, digest);
    expect(code).toMatchObject({
      repo, tag, commit, digest,
      subjectName: "tinfoil-deployment.json",
      measurement: { registers: ["1".repeat(96), "2".repeat(96), "3".repeat(96)] },
      shape: { cpus: 2, memoryMB: 4096, gpus: 0, disks: 1 },
    });
  });

  it.each([
    "wrong repository", "wrong tag", "wrong digest", "wrong root",
    "missing timestamp", "altered timestamp", "altered payload", "public log with private timestamp",
  ])("rejects %s", async (name) => {
    const bundle = JSON.parse(new TextDecoder().decode(fixture("private-source.json"))) as WireBundle;
    const material = bundle.verificationMaterial!;
    let expectedRepo = repo;
    let expectedTag = tag;
    let expectedDigest = digest;
    let githubTrustRootJSON: Uint8Array | undefined;
    switch (name) {
      case "wrong repository":
        expectedRepo = "another/repository";
        break;
      case "wrong tag":
        expectedTag = "v1.0.2";
        break;
      case "wrong digest":
        expectedDigest = "0".repeat(64);
        break;
      case "wrong root":
        githubTrustRootJSON = utf8Encode(trustedRootJSON);
        break;
      case "missing timestamp":
        delete material.timestampVerificationData;
        break;
      case "altered timestamp": {
        const timestamp = material.timestampVerificationData!.rfc3161Timestamps![0];
        const der = Buffer.from(timestamp.signedTimestamp, "base64");
        der[der.length - 1] ^= 1;
        timestamp.signedTimestamp = der.toString("base64");
        break;
      }
      case "altered payload": {
        const envelope = bundle.dsseEnvelope!;
        const payload = Buffer.from(envelope.payload, "base64");
        envelope.payload = Buffer.concat([payload, Buffer.from(" ")]).toString("base64");
        break;
      }
      case "public log with private timestamp":
        material.tlogEntries = [JSON.parse(new TextDecoder().decode(fixture("public-log-entry.json")))];
        break;
    }
    await expect(authenticateCode(
      utf8Encode(JSON.stringify(bundle)), expectedRepo, expectedTag, expectedDigest, { githubTrustRootJSON },
    )).rejects.toThrow();
  });

  it("verifies the test witness chain while rejecting its non-production workflow", async () => {
    const bundle = fixture("private-freshness.json");
    const identity = "^https://github\\.com/tinfoilsh/freshness-witness/\\.github/workflows/private\\.yml@refs/heads/codex/private-repo-v3-e2e$";
    const verified = await verifyBundleWithIdentity(bundle, identity, digest);
    expect(verified.tlogTimestamps).toEqual([]);
    expect(verified.authenticatedTimestamps).toHaveLength(1);
    expect(verified.authenticatedTimestamps[0].toISOString()).toMatch(/^2026-08-28T10:11:/);
    expect(verified.statement.predicate).toMatchObject({
      endorses: { repo, tag, commit, subject: { name: "tinfoil-deployment.json", digest: `sha256:${digest}` } },
    });
    // This captured workflow used a test ref; production must require main.
    await expect(authenticateFreshness(bundle, {
      repo, tag, commit, digest, subjectName: "tinfoil-deployment.json",
    }, new Date("2026-08-28T10:12:00Z"))).rejects.toThrow();
  });
});
