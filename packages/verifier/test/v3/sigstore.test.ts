/**
 * Tests for the certificate-signed half of the Sigstore module: trusted-root
 * parsing (trusted-root.ts), bundle decoding (bundle.ts) and certificate
 * bundle verification with the workflow identity policy (certificate.ts).
 *
 * The bundles come from the shared tinfoil-conformance vectors (see
 * helpers/conformance.ts for where they are read from): each vector's
 * document carries the bundles, and its input the synthetic trusted root they
 * were signed under (or none, for the embedded production root). The suites
 * that need the vectors are skipped when the checkout is not available; the
 * embedded-root and pattern tests run regardless.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { sha256, toHex, utf8 } from "../../src/v3/internal/bytes.js";
import { strictParse, type JsonValue } from "../../src/v3/internal/json/index.js";
import {
  BUNDLE_MEDIA_TYPE,
  bundleBytes,
  IN_TOTO_PAYLOAD_TYPE,
  MAX_BUNDLE_SIZE,
  parseBundle,
  parseBundleBytes,
} from "../../src/v3/internal/sigstore/bundle.js";
import {
  GITHUB_OIDC_ISSUER,
  RUNNER_ENVIRONMENT_GITHUB_HOSTED,
  verifyCertificateBundle,
  workflowIdentityPattern,
} from "../../src/v3/internal/sigstore/certificate.js";
import { embeddedTrustedRoot, parseTrustedRoot, TRUSTED_ROOT_MEDIA_TYPE, type TrustedRoot } from "../../src/v3/internal/sigstore/trusted-root.js";
import { SIGSTORE_TRUSTED_ROOT_JSON } from "../../src/v3/trust/sigstore-trusted-root.js";
import {
  conformanceAvailable,
  decodeDocument,
  loadFixture,
  repoOf,
  sigstoreCollateral,
  syntheticTrustedRoot,
  vectorsTitle,
  type SigstoreEntry,
} from "./helpers/conformance.js";

/** The Sigstore material of one conformance vector. */
interface Fixture {
  readonly id: string;
  readonly expected: "accept" | "reject";
  readonly repo: string;
  /** The synthetic trusted root the bundles were signed under; undefined for the embedded production root. */
  readonly trusted_root: unknown;
  readonly collateral: readonly SigstoreEntry[];
}

/** The vector a fixture id names: the golden and real-frozen documents by name, anything else a provenance case. */
function vectorPath(id: string): string {
  if (id === "golden-happy") return "golden/golden-happy.json";
  if (id === "real-sev-inference-tinfoil") return "real-frozen/real-sev-inference-tinfoil.json";
  return `provenance/${id}.json`;
}

function fixture(id: string): Fixture {
  const f = loadFixture(vectorPath(id));
  return {
    id: f.id,
    expected: f.expected.accepted ? "accept" : "reject",
    repo: repoOf(f),
    trusted_root: syntheticTrustedRoot(f),
    collateral: sigstoreCollateral(decodeDocument(f)),
  };
}

/** A plain value as the strict parser would read it. */
function toJson(value: unknown): JsonValue {
  return strictParse(utf8(JSON.stringify(value)));
}

function entry(f: Fixture, collateralId: string): SigstoreEntry {
  const e = f.collateral.find((c) => c.id === collateralId);
  if (e === undefined) throw new Error(`${f.id} has no ${collateralId} collateral`);
  return e;
}

function bundleOf(f: Fixture, collateralId: string): JsonValue {
  return toJson(entry(f, collateralId).data.sigstore_bundle);
}

/** A copy of a bundle with `mutate` applied, re-read by the strict parser. */
function mutated(bundle: unknown, mutate: (b: Record<string, any>) => void): JsonValue {
  const copy = structuredClone(bundle) as Record<string, any>;
  mutate(copy);
  return toJson(copy);
}

function rootOf(f: Fixture): Promise<TrustedRoot> {
  return f.trusted_root === undefined ? embeddedTrustedRoot() : parseTrustedRoot(utf8(JSON.stringify(f.trusted_root)));
}

const decode = (b64: string): Uint8Array => new Uint8Array(Buffer.from(b64, "base64"));

/** The identity accepted for code releases: any workflow file of the repository, run from a tag. */
const codeIdentity = (repo: string): RegExp => workflowIdentityPattern(repo, "[^/@]+", "refs/tags/[^@]+");
/** The identity accepted for platform endorsements. */
const platformIdentity = workflowIdentityPattern("tinfoilsh/cvmimage", "platform-release\\.yml", "refs/tags/platform-v[0-9][^@]*");

const withoutVectors = !conformanceAvailable();

// The vectors shared across suites. They are read in beforeAll of the suites
// that use them (not at import time) so a missing checkout only skips those.
let golden: Fixture;
let real: Fixture;
let goldenCode: SigstoreEntry;
let goldenPlatform: SigstoreEntry;
let realCode: SigstoreEntry;
let realPlatform: SigstoreEntry;

function loadShared(): void {
  if (golden !== undefined) return;
  golden = fixture("golden-happy");
  real = fixture("real-sev-inference-tinfoil");
  goldenCode = entry(golden, "sigstore-code");
  goldenPlatform = entry(golden, "sigstore-platform");
  realCode = entry(real, "code");
  realPlatform = entry(real, "platform");
}

async function rejects(p: Promise<unknown>, pattern: RegExp): Promise<void> {
  await expect(p).rejects.toThrow(pattern);
}

describe("trusted root", () => {
  const embeddedJson = JSON.parse(SIGSTORE_TRUSTED_ROOT_JSON) as Record<string, any>;

  it("parses the embedded production root", async () => {
    const root = await embeddedTrustedRoot();
    expect(root.certificateAuthorities).toHaveLength(embeddedJson.certificateAuthorities.length);
    expect(root.transparencyLogs).toHaveLength(embeddedJson.tlogs.length);
    expect(root.ctLogs).toHaveLength(embeddedJson.ctlogs.length);
    expect(root.timestampAuthorities).toHaveLength(embeddedJson.timestampAuthorities.length);
    expect(root.json).toBeInstanceOf(Map);
    // Logs are named by the id the root states, as log entries name them.
    for (const [i, log] of root.transparencyLogs.entries()) {
      expect(log.logId).toBe(toHex(decode(embeddedJson.tlogs[i].logId.keyId)));
      expect(log.publicKey.type).toBe("public");
      expect(log.validFrom).toEqual(new Date(embeddedJson.tlogs[i].publicKey.validFor.start));
    }
    for (const [i, log] of root.ctLogs.entries()) {
      expect(log.logId).toBe(toHex(decode(embeddedJson.ctlogs[i].logId.keyId)));
    }
  });

  it("imports every key type the production logs use", async () => {
    const root = await embeddedTrustedRoot();
    const algorithms = root.transparencyLogs.map((log) => log.publicKey.algorithm.name).sort();
    expect(algorithms).toEqual(["ECDSA", "Ed25519"]);
  });

  it("orders certificate chains root first and keeps validity windows", async () => {
    const root = await embeddedTrustedRoot();
    for (const [i, ca] of root.certificateAuthorities.entries()) {
      const wire = embeddedJson.certificateAuthorities[i];
      const certs = wire.certChain.certificates as { rawBytes: string }[];
      expect(ca.chainDer).toHaveLength(certs.length);
      expect(ca.chainDer[0]).toEqual(decode(certs[certs.length - 1]!.rawBytes));
      expect(ca.chainDer[ca.chainDer.length - 1]).toEqual(decode(certs[0]!.rawBytes));
      expect(ca.validFrom).toEqual(new Date(wire.validFor.start));
      if (wire.validFor.end === undefined) expect(ca.validTo).toBeUndefined();
      else expect(ca.validTo).toEqual(new Date(wire.validFor.end));
    }
    expect(root.certificateAuthorities.some((ca) => ca.validTo !== undefined)).toBe(true);
    expect(root.certificateAuthorities.some((ca) => ca.validTo === undefined)).toBe(true);
  });

  it("shares one parsed embedded root across calls", async () => {
    expect(await embeddedTrustedRoot()).toBe(await embeddedTrustedRoot());
  });

  it("rejects text that is not a JSON object", async () => {
    await rejects(parseTrustedRoot(utf8("null")), /is null/);
    await rejects(parseTrustedRoot(utf8("[]")), /cannot unmarshal/);
    await rejects(parseTrustedRoot(utf8("{")), /parsing trusted root/);
  });

  it("exposes the media type", () => {
    expect(TRUSTED_ROOT_MEDIA_TYPE).toBe(embeddedJson.mediaType);
  });

  describe.skipIf(withoutVectors)(vectorsTitle("synthetic root"), () => {
    beforeAll(loadShared);

    it("parses a synthetic root", async () => {
      const root = await rootOf(golden);
      expect(root.certificateAuthorities).toHaveLength(1);
      expect(root.transparencyLogs).toHaveLength(1);
      expect(root.ctLogs).toHaveLength(1);
      expect(root.timestampAuthorities).toHaveLength(0);
      const wire = golden.trusted_root as Record<string, any>;
      // The synthetic logs state the id SHA-256 of the key yields.
      const keyId = toHex(await sha256(decode(wire.tlogs[0].publicKey.rawBytes)));
      expect(root.transparencyLogs[0]!.logId).toBe(keyId);
      expect(root.transparencyLogs[0]!.validTo).toBeUndefined();
    });

    it("derives the log id from the key when the root states none", async () => {
      const wire = structuredClone(golden.trusted_root) as Record<string, any>;
      delete wire.tlogs[0].logId;
      const root = await parseTrustedRoot(utf8(JSON.stringify(wire)));
      expect(root.transparencyLogs[0]!.logId).toBe(toHex(await sha256(decode(wire.tlogs[0].publicKey.rawBytes))));
    });

    const withRoot = (mutate: (r: Record<string, any>) => void): Uint8Array => {
      const wire = structuredClone(golden.trusted_root) as Record<string, any>;
      mutate(wire);
      return utf8(JSON.stringify(wire));
    };

    it.each<[string, (r: Record<string, any>) => void, RegExp]>([
      ["a wrong media type", (r) => (r.mediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.2"), /media type/],
      ["an unknown member", (r) => (r.extra = 1), /unknown object member name "extra"/],
      ["an unknown log member", (r) => (r.tlogs[0].extra = 1), /unknown object member name "extra"/],
      ["an unsupported key type", (r) => (r.tlogs[0].publicKey.keyDetails = "PKIX_RSA_PKCS1V15_2048_SHA256"), /unsupported transparency log key type/],
      ["a key that is not the declared type", (r) => (r.tlogs[0].publicKey.keyDetails = "PKIX_ED25519"), /importing transparency log key/],
      ["an unsupported hash algorithm", (r) => (r.ctlogs[0].hashAlgorithm = "SHA2_384"), /hash algorithm/],
      ["a validity window without a start", (r) => delete r.certificateAuthorities[0].validFor.start, /no start/],
      ["a validity window that is not RFC 3339", (r) => (r.certificateAuthorities[0].validFor.start = "yesterday"), /not RFC 3339/],
      ["a validity window on an impossible day", (r) => (r.certificateAuthorities[0].validFor.start = "2025-02-30T00:00:00Z"), /not a real time/],
      ["a validity window with an impossible clock", (r) => (r.certificateAuthorities[0].validFor.start = "2025-02-01T24:00:00Z"), /not a real time|not RFC 3339/],
      ["a validity window ending before it starts", (r) => (r.ctlogs[0].publicKey.validFor.end = "2000-01-01T00:00:00Z"), /ends before it starts/],
      ["an empty certificate chain", (r) => (r.certificateAuthorities[0].certChain.certificates = []), /empty certificate chain/],
      ["a certificate that is not base64", (r) => (r.certificateAuthorities[0].certChain.certificates[0].rawBytes = "*"), /illegal base64/],
      ["a log id that is not 32 bytes", (r) => (r.tlogs[0].logId.keyId = "AQID"), /not 32 bytes/],
      ["a null log", (r) => (r.ctlogs = [null]), /is null/],
    ])("rejects %s", async (_what, mutate, pattern) => {
      await rejects(parseTrustedRoot(withRoot(mutate)), pattern);
    });
  });
});

describe("bundle", () => {
  it("rejects null", () => {
    expect(() => parseBundle(null)).toThrow(/bundle is null/);
  });

  it("rejects a bundle over the size limit", () => {
    const huge = new Map<string, JsonValue>([["mediaType", "x".repeat(MAX_BUNDLE_SIZE)]]);
    expect(() => parseBundle(huge)).toThrow(/exceeds/);
  });

  it("bounds wire bytes before parsing them", () => {
    expect(() => parseBundleBytes(new Uint8Array(MAX_BUNDLE_SIZE + 1))).toThrow(/exceeds/);
    expect(() => parseBundleBytes(utf8("null"))).toThrow(/bundle is null/);
  });

  describe.skipIf(withoutVectors)(vectorsTitle("decoding"), () => {
    let goldenBundle: Record<string, any>;
    beforeAll(() => {
      loadShared();
      goldenBundle = goldenCode.data.sigstore_bundle as Record<string, any>;
    });

    it("decodes a certificate-signed bundle", () => {
      const b = parseBundle(toJson(goldenBundle));
      expect(b.mediaType).toBe(BUNDLE_MEDIA_TYPE);
      expect(b.certificate).toEqual(decode(goldenBundle.verificationMaterial.certificate.rawBytes));
      expect(b.publicKeyHint).toBeUndefined();
      expect(b.rfc3161Timestamps).toEqual([]);
      expect(b.dsse.payloadType).toBe(IN_TOTO_PAYLOAD_TYPE);
      expect(b.dsse.payload).toEqual(decode(goldenBundle.dsseEnvelope.payload));
      expect(b.dsse.signature).toEqual(decode(goldenBundle.dsseEnvelope.signatures[0].sig));
      expect(b.dsse.keyId).toBe("");
      expect(b.tlogEntries).toHaveLength(1);
      const wire = goldenBundle.verificationMaterial.tlogEntries[0];
      const e = b.tlogEntries[0]!;
      expect(e.logId).toBe(toHex(decode(wire.logId.keyId)));
      expect(e.kind).toBe("dsse");
      expect(e.version).toBe("0.0.1");
      expect(e.integratedTime).toBe(BigInt(wire.integratedTime));
      expect(e.canonicalizedBody).toEqual(decode(wire.canonicalizedBody));
      expect(e.inclusionPromise).toEqual(decode(wire.inclusionPromise.signedEntryTimestamp));
      expect(e.inclusionProof).toEqual({
        logIndex: 0n,
        rootHash: decode(wire.inclusionProof.rootHash),
        treeSize: 1n,
        hashes: [],
        checkpoint: wire.inclusionProof.checkpoint.envelope,
      });
      expect(b.json).toBeInstanceOf(Map);
    });

    it("rejects a null inclusion proof hash", () => {
      const wire = realCode.data.sigstore_bundle as Record<string, any>;
      expect(() => parseBundle(mutated(wire, (w) => (w.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0] = null)))).toThrow(
        /hash is not a string/,
      );
    });

    it("decodes a production bundle whose timestamp data is an empty record", () => {
      const wire = realCode.data.sigstore_bundle as Record<string, any>;
      expect(wire.verificationMaterial.timestampVerificationData).toEqual({});
      const b = parseBundle(toJson(wire));
      expect(b.rfc3161Timestamps).toEqual([]);
      expect(b.tlogEntries[0]!.inclusionProof!.hashes).toHaveLength(wire.verificationMaterial.tlogEntries[0].inclusionProof.hashes.length);
      expect(b.tlogEntries[0]!.inclusionProof!.logIndex).toBe(BigInt(wire.verificationMaterial.tlogEntries[0].inclusionProof.logIndex));
    });

    it("keeps the DSSE key id and a public key hint", () => {
      const b = parseBundle(
        mutated(goldenBundle, (w) => {
          w.dsseEnvelope.signatures[0].keyid = "key-1";
          delete w.verificationMaterial.certificate;
          w.verificationMaterial.publicKey = { hint: "hint-1" };
        }),
      );
      expect(b.dsse.keyId).toBe("key-1");
      expect(b.publicKeyHint).toBe("hint-1");
      expect(b.certificate).toBeUndefined();
    });

    it("reads integer fields written as numbers and omits a zero integration time", () => {
      const b = parseBundle(
        mutated(goldenBundle, (w) => {
          w.verificationMaterial.tlogEntries[0].integratedTime = 0;
          w.verificationMaterial.tlogEntries[0].inclusionProof.treeSize = 7;
        }),
      );
      expect(b.tlogEntries[0]!.integratedTime).toBeUndefined();
      expect(b.tlogEntries[0]!.inclusionProof!.treeSize).toBe(7n);
    });

    it("rejects the legacy certificate-chain layout", () => {
      const legacy = fixture("p3");
      expect(() => parseBundle(bundleOf(legacy, "sigstore-code"))).toThrow(/legacy bundle format not supported/);
    });

    it("rejects an envelope with two signatures", () => {
      expect(() => parseBundle(bundleOf(fixture("p4-two-sigs"), "sigstore-code"))).toThrow(/exactly one signature, got 2/);
    });

    it("rejects an envelope with no signature", () => {
      expect(() => parseBundle(bundleOf(fixture("p4-zero-sigs"), "sigstore-code"))).toThrow(/exactly one signature, got 0/);
    });

    it.each<[string, (b: Record<string, any>) => void, RegExp]>([
      ["the versioned media type", (w) => (w.mediaType = "application/vnd.dev.sigstore.bundle+json;version=0.3"), /media type/],
      ["an older media type", (w) => (w.mediaType = "application/vnd.dev.sigstore.bundle.v0.2+json"), /media type/],
      ["an unknown member", (w) => (w.extra = true), /unknown object member name "extra"/],
      ["an unknown verification material member", (w) => (w.verificationMaterial.extra = true), /unknown object member name "extra"/],
      ["a certificate chain beside the certificate", (w) => (w.verificationMaterial.x509CertificateChain = { certificates: [] }), /legacy bundle format/],
      ["a certificate beside a key hint", (w) => (w.verificationMaterial.publicKey = { hint: "h" }), /exactly one of a certificate or a public key hint/],
      ["neither certificate nor key hint", (w) => delete w.verificationMaterial.certificate, /exactly one of a certificate or a public key hint/],
      ["an empty certificate", (w) => (w.verificationMaterial.certificate.rawBytes = ""), /certificate is empty/],
      ["a certificate that is not canonical base64", (w) => (w.verificationMaterial.certificate.rawBytes = "AB"), /base64/],
      ["a message signature", (w) => (w.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: "" }, signature: "" }), /message signature/],
      ["a missing envelope", (w) => delete w.dsseEnvelope, /no DSSE envelope/],
      ["a null envelope", (w) => (w.dsseEnvelope = null), /no DSSE envelope/],
      ["an empty payload", (w) => (w.dsseEnvelope.payload = ""), /no payload/],
      ["an empty payload type", (w) => (w.dsseEnvelope.payloadType = ""), /no payload type/],
      ["an empty signature", (w) => (w.dsseEnvelope.signatures[0].sig = ""), /signature is empty/],
      ["a null signature", (w) => (w.dsseEnvelope.signatures = [null]), /signature is null/],
      ["an unknown signature member", (w) => (w.dsseEnvelope.signatures[0].extra = 1), /unknown object member name "extra"/],
      ["a log id that is not 32 bytes", (w) => (w.verificationMaterial.tlogEntries[0].logId.keyId = "AQID"), /not 32 bytes/],
      ["an entry without a kind", (w) => (w.verificationMaterial.tlogEntries[0].kindVersion.kind = ""), /no kind and version/],
      ["an entry without a body", (w) => (w.verificationMaterial.tlogEntries[0].canonicalizedBody = ""), /no body/],
      ["a null entry", (w) => (w.verificationMaterial.tlogEntries = [null]), /is null/],
      ["a negative integration time", (w) => (w.verificationMaterial.tlogEntries[0].integratedTime = "-1"), /not a non-negative integer/],
      ["a fractional integration time", (w) => (w.verificationMaterial.tlogEntries[0].integratedTime = 1.5), /not an integer/],
      ["an integration time beyond int64", (w) => (w.verificationMaterial.tlogEntries[0].integratedTime = "9223372036854775808"), /overflows int64/],
      ["an integration time of another type", (w) => (w.verificationMaterial.tlogEntries[0].integratedTime = true), /not an integer/],
      ["an empty inclusion promise", (w) => (w.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp = ""), /promise is empty/],
      ["a proof without a checkpoint", (w) => (w.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint = {}), /no checkpoint/],
      ["a proof without a root hash", (w) => (w.verificationMaterial.tlogEntries[0].inclusionProof.rootHash = ""), /no root hash/],
      ["an empty timestamp", (w) => (w.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [{ signedTimestamp: "" }] }), /timestamp is empty/],
      ["a null document", (w) => Object.keys(w).forEach((k) => delete w[k]), /media type/],
    ])("rejects %s", (_what, mutate, pattern) => {
      expect(() => parseBundle(mutated(goldenBundle, mutate))).toThrow(pattern);
    });

    it("serializes a bundle back to the value it was read from", () => {
      const bytes = bundleBytes(toJson(goldenBundle));
      expect(JSON.parse(new TextDecoder().decode(bytes))).toEqual(goldenBundle);
      expect(bytes.length).toBeLessThanOrEqual(MAX_BUNDLE_SIZE);
    });
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("verifyCertificateBundle"), () => {
  let goldenRoot: Promise<TrustedRoot>;
  beforeAll(() => {
    loadShared();
    goldenRoot = rootOf(golden);
  });

  it("verifies the code bundle of a synthetic release", async () => {
    const digest = goldenCode.data.digest!;
    const v = await verifyCertificateBundle(await goldenRoot, parseBundle(bundleOf(golden, "sigstore-code")), codeIdentity(golden.repo), digest);
    expect(v.identity.subjectAlternativeName).toBe(`https://github.com/${golden.repo}/.github/workflows/release.yml@refs/tags/${goldenCode.data.tag}`);
    expect(v.identity.issuer).toBe(GITHUB_OIDC_ISSUER);
    expect(v.identity.runnerEnvironment).toBe(RUNNER_ENVIRONMENT_GITHUB_HOSTED);
    expect(v.identity.sourceRepositoryRef).toBe(`refs/tags/${goldenCode.data.tag}`);
    expect(v.identity.sourceRepositoryDigest).toMatch(/^[0-9a-f]{40}$/);
    expect(v.identity.sourceRepositoryIdentifier).toBe("");
    expect(v.identity.sourceRepositoryOwnerIdentifier).toBe("");
    expect(v.payload).toEqual(decode((goldenCode.data.sigstore_bundle as Record<string, any>).dsseEnvelope.payload));
    expect(v.verifiedLogTime).toEqual(new Date("2025-01-01T00:00:01Z"));
  });

  it("verifies the platform bundle under the platform identity only", async () => {
    const bundle = parseBundle(bundleOf(golden, "sigstore-platform"));
    const digest = goldenPlatform.data.digest!;
    const v = await verifyCertificateBundle(await goldenRoot, bundle, platformIdentity, digest);
    expect(v.identity.subjectAlternativeName).toBe("https://github.com/tinfoilsh/cvmimage/.github/workflows/platform-release.yml@refs/tags/platform-v1.0.0");
    await rejects(verifyCertificateBundle(await goldenRoot, bundle, codeIdentity(golden.repo), digest), /does not match the expected workflow identity/);
    await rejects(verifyCertificateBundle(await goldenRoot, parseBundle(bundleOf(golden, "sigstore-code")), platformIdentity, goldenCode.data.digest!), /does not match the expected workflow identity/);
  });

  it("compares digests case-insensitively", async () => {
    const digest = goldenCode.data.digest!.toUpperCase();
    const v = await verifyCertificateBundle(await goldenRoot, parseBundle(bundleOf(golden, "sigstore-code")), codeIdentity(golden.repo), digest);
    expect(v.identity.issuer).toBe(GITHUB_OIDC_ISSUER);
  });

  it("rejects a digest no subject carries", async () => {
    const other = "0".repeat(64);
    await rejects(verifyCertificateBundle(await goldenRoot, parseBundle(bundleOf(golden, "sigstore-code")), codeIdentity(golden.repo), other), /subject\[0\] digest/);
  });

  it("rejects a digest that is not hex SHA-256", async () => {
    await rejects(verifyCertificateBundle(await goldenRoot, parseBundle(bundleOf(golden, "sigstore-code")), codeIdentity(golden.repo), "abc"), /not hex SHA-256/);
  });

  it("binds a named subject when one is requested", async () => {
    const multi = fixture("provenance-pos-multi-subject");
    const bundle = parseBundle(bundleOf(multi, "sigstore-code"));
    const root = await rootOf(multi);
    const digest = entry(multi, "sigstore-code").data.digest!;
    await verifyCertificateBundle(root, bundle, codeIdentity(multi.repo), digest, "cip");
    await verifyCertificateBundle(root, bundle, codeIdentity(multi.repo), "11".repeat(32), "extra");
    await rejects(verifyCertificateBundle(root, bundle, codeIdentity(multi.repo), digest, "extra"), /subject "extra" digest does not match/);
    await rejects(verifyCertificateBundle(root, bundle, codeIdentity(multi.repo), digest, "missing"), /exactly once, found 0/);
    // Without a name, only subject 0 binds: the second subject's digest is not accepted.
    await rejects(verifyCertificateBundle(root, bundle, codeIdentity(multi.repo), "11".repeat(32)), /subject\[0\] digest/);
  });

  it("rejects a bundle whose payload is not an in-toto statement", async () => {
    const bundle = parseBundle(mutated(goldenCode.data.sigstore_bundle, (w) => (w.dsseEnvelope.payloadType = "application/json")));
    await rejects(verifyCertificateBundle(await goldenRoot, bundle, codeIdentity(golden.repo), goldenCode.data.digest!), /unsupported DSSE payload type/);
  });

  it("rejects a bundle without a certificate", async () => {
    const bundle = parseBundle(
      mutated(goldenCode.data.sigstore_bundle, (w) => {
        delete w.verificationMaterial.certificate;
        w.verificationMaterial.publicKey = { hint: "h" };
      }),
    );
    await rejects(verifyCertificateBundle(await goldenRoot, bundle, codeIdentity(golden.repo), goldenCode.data.digest!), /no signing certificate/);
  });

  it("rejects a bundle whose signing time is only the bundle's own claim", async () => {
    // Without the first entry's inclusion promise, the integration time is
    // unsigned: the inclusion proof covers the entry body only, so the
    // bundle could state any time inside the certificate's window.
    const bundle = parseBundle(
      mutated(goldenCode.data.sigstore_bundle, (w) => {
        delete w.verificationMaterial.tlogEntries[0].inclusionPromise;
      }),
    );
    await rejects(verifyCertificateBundle(await goldenRoot, bundle, codeIdentity(golden.repo), goldenCode.data.digest!), /no verified observer timestamp/);
  });

  it("rejects a payload altered after signing", async () => {
    const bundle = parseBundle(
      mutated(goldenCode.data.sigstore_bundle, (w) => {
        const statement = JSON.parse(Buffer.from(w.dsseEnvelope.payload, "base64").toString()) as Record<string, unknown>;
        statement.extra = 1;
        w.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
      }),
    );
    await rejects(verifyCertificateBundle(await goldenRoot, bundle, codeIdentity(golden.repo), goldenCode.data.digest!), /verifying bundle/);
  });

  it("verifies a production code bundle against the embedded root", async () => {
    const root = await embeddedTrustedRoot();
    const digest = realCode.data.digest!;
    const v = await verifyCertificateBundle(root, parseBundle(bundleOf(real, "code")), codeIdentity(real.repo), digest);
    expect(v.identity.subjectAlternativeName).toBe(`https://github.com/${real.repo}/.github/workflows/tinfoil-release-publish.yml@refs/tags/${realCode.data.tag}`);
    expect(v.identity.issuer).toBe(GITHUB_OIDC_ISSUER);
    expect(v.identity.runnerEnvironment).toBe(RUNNER_ENVIRONMENT_GITHUB_HOSTED);
    expect(v.identity.sourceRepositoryRef).toBe(`refs/tags/${realCode.data.tag}`);
    expect(v.identity.sourceRepositoryDigest).toMatch(/^[0-9a-f]{40}$/);
    expect(v.identity.sourceRepositoryIdentifier).toMatch(/^[0-9]+$/);
    expect(v.identity.sourceRepositoryOwnerIdentifier).toMatch(/^[0-9]+$/);
    const wire = realCode.data.sigstore_bundle as Record<string, any>;
    expect(v.verifiedLogTime).toEqual(new Date(Number(wire.verificationMaterial.tlogEntries[0].integratedTime) * 1000));
  });

  it("binds a production platform bundle to its own repository", async () => {
    const root = await embeddedTrustedRoot();
    const bundle = parseBundle(bundleOf(real, "platform"));
    const digest = realPlatform.data.digest!;
    const v = await verifyCertificateBundle(root, bundle, codeIdentity(realPlatform.data.repo!), digest);
    expect(v.identity.subjectAlternativeName).toContain(`/${realPlatform.data.repo}/`);
    await rejects(verifyCertificateBundle(root, bundle, platformIdentity, digest), /does not match the expected workflow identity/);
  });

  it("rejects a synthetic bundle under the embedded root", async () => {
    await rejects(
      verifyCertificateBundle(await embeddedTrustedRoot(), parseBundle(bundleOf(golden, "sigstore-code")), codeIdentity(golden.repo), goldenCode.data.digest!),
      /verifying bundle/,
    );
  });

  describe("provenance fixtures", () => {
    // Fixtures whose mutation belongs to another layer are not run here:
    // p1 (no code collateral: document decoding), p13-* (predicate parsing),
    // p-code-ref-not-tag, p-code-tag-mismatch and p-code-bad-commit (the
    // release tag and commit read from the certificate by the endorsement
    // layer), and the freshness fixtures (the freshness window). p3 and
    // p4-* are bundle-decoding rejections, covered above.
    const accepted = ["provenance-happy", "provenance-pos-wildcard-workflow", "provenance-pos-other-tag", "provenance-pos-multi-subject"];
    const rejected: [string, RegExp][] = [
      ["p5", /verifying bundle: .*certificate chain/],
      ["p6", /loading trusted root: .*CT logs/],
      ["p7", /verifying bundle: .*tlog entries/],
      ["p8", /verifying bundle: .*certificate validity/],
      ["p9", /verifying bundle: .*DSSE signature/],
      ["p10", /subject\[0\] digest/],
      ["p11-san", /does not match the expected workflow identity/],
      ["p11-issuer", /is not GitHub Actions/],
      ["p11-runner", /is not GitHub-hosted/],
      ["p12", /verifying bundle: .*Duplicate SCT/],
      ["p14-ref", /does not match the expected workflow identity/],
      ["p14-path", /does not match the expected workflow identity/],
      ["p-no-subject", /statement has no subject/],
    ];

    it.each(accepted)("accepts %s", async (id) => {
      const f = fixture(id);
      expect(f.expected).toBe("accept");
      const code = entry(f, "sigstore-code");
      const v = await verifyCertificateBundle(await rootOf(f), parseBundle(toJson(code.data.sigstore_bundle)), codeIdentity(f.repo), code.data.digest!);
      expect(v.identity.subjectAlternativeName).toMatch(codeIdentity(f.repo));
    });

    it.each(rejected)("rejects %s", async (id, pattern) => {
      const f = fixture(id);
      expect(f.expected).toBe("reject");
      const code = entry(f, "sigstore-code");
      await rejects(verifyCertificateBundle(await rootOf(f), parseBundle(toJson(code.data.sigstore_bundle)), codeIdentity(f.repo), code.data.digest!), pattern);
    });
  });
});

describe("workflowIdentityPattern", () => {
  const san = (repo: string, workflow = "release.yml", ref = "refs/tags/v1.0.0"): string =>
    `https://github.com/${repo}/.github/workflows/${workflow}@${ref}`;

  it("treats the repository as a literal", () => {
    const p = workflowIdentityPattern("tinfoilsh/cvm.image", "[^/@]+", "refs/tags/[^@]+");
    expect(p.test(san("tinfoilsh/cvm.image"))).toBe(true);
    expect(p.test(san("tinfoilsh/cvmXimage"))).toBe(false);
    const q = workflowIdentityPattern("a+b/c(d)", "[^/@]+", "refs/tags/[^@]+");
    expect(q.test(san("a+b/c(d)"))).toBe(true);
    expect(q.test(san("aab/cd"))).toBe(false);
  });

  it("inserts the workflow and ref fragments as written", () => {
    const p = workflowIdentityPattern("tinfoilsh/cvmimage", "platform-release\\.yml", "refs/tags/platform-v[0-9][^@]*");
    expect(p.test(san("tinfoilsh/cvmimage", "platform-release.yml", "refs/tags/platform-v1.2.3"))).toBe(true);
    expect(p.test(san("tinfoilsh/cvmimage", "platform-releaseXyml", "refs/tags/platform-v1"))).toBe(false);
    expect(p.test(san("tinfoilsh/cvmimage", "platform-release.yml", "refs/tags/platform-vX"))).toBe(false);
    expect(p.test(san("tinfoilsh/cvmimage", "platform-release.yml", "refs/tags/v1"))).toBe(false);
  });

  it("is anchored at both ends", () => {
    const p = workflowIdentityPattern("tinfoilsh/repo", "[^/@]+", "refs/tags/[^@]+");
    expect(p.test(san("tinfoilsh/repo"))).toBe(true);
    expect(p.test(`x${san("tinfoilsh/repo")}`)).toBe(false);
    expect(p.test(`${san("tinfoilsh/repo")}@extra`)).toBe(false);
    expect(p.test(san("tinfoilsh/repo", "nested/release.yml"))).toBe(false);
    expect(p.test(san("tinfoilsh/repo", "release.yml", "refs/heads/main"))).toBe(false);
    expect(p.test(san("tinfoilsh/repo/other"))).toBe(false);
  });

  it("builds the documented pattern", () => {
    // `source` re-escapes '/' on some engines; compare without that.
    const source = workflowIdentityPattern("o/r", "w", "ref").source.replace(/\\\//g, "/");
    expect(source).toBe("^https://github\\.com/o/r/\\.github/workflows/(?:w)@(?:ref)$");
  });

  it("keeps an alternation inside a fragment within the anchors", () => {
    const pattern = workflowIdentityPattern("o/r", "w", "refs/tags/v1|refs/heads/main");
    expect(pattern.test("https://github.com/o/r/.github/workflows/w@refs/heads/main")).toBe(true);
    expect(pattern.test("https://github.com/x/y/.github/workflows/w@refs/heads/main")).toBe(false);
    expect(workflowIdentityPattern("o/r", "w", "ref|.*").test("https://github.com/x/y/.github/workflows/w@ref")).toBe(false);
  });
});
