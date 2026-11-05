/**
 * Tests for the key-signed half of the Sigstore module: key hints and pinned
 * keys, key-signed bundle verification (keyed.ts), and RFC 3161 timestamps
 * with the canonical statement input (timestamp.ts).
 *
 * Key-signed bundles are built here with WebCrypto: a fresh signing key, a
 * transparency log key (ECDSA or Ed25519) that signs checkpoints over small
 * Merkle trees, and a trusted root listing that log. The shared
 * tinfoil-conformance vectors (see helpers/conformance.ts) supply the rest:
 * `approval-bundle/*.json` (stage v3-authenticate-approval) carry key-signed
 * bundles, the pinned keys and the artifact digest with the expected verdict,
 * and `rfc3161/*.json` (stage v3-verify-timestamp) carry timestamp responses
 * from synthetic authorities with the input they timestamp, the trusted root
 * that lists the authorities and the expected verdict; the negative cases no
 * vector covers are derived from the granted-p256 vector's bytes. Those
 * suites skip when the vectors are not available. fixtures/sigstore/
 * rfc3161-production.json is one response from the production authority that
 * verifies under the embedded trusted root.
 */
import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { concat, sha256, toHex, utf8 } from "../src/internal/bytes.js";
import { strictParse } from "../src/internal/json/index.js";
import { IN_TOTO_PAYLOAD_TYPE, parseBundle } from "../src/internal/sigstore/bundle.js";
import {
  keyHint,
  MAX_LOG_RECEIPTS,
  pinnedKeys,
  verifyKeyedBundle,
  verifyMerkleInclusion,
  type PinnedKey,
} from "../src/internal/sigstore/keyed.js";
import {
  endorsementReference,
  MAX_STATEMENT_SIZE,
  MAX_TIMESTAMP_SIZE,
  parseTimestampResponse,
  preAuthEncoding,
  SIGSTORE_TIMESTAMP_POLICY,
  STATUS_GRANTED,
  timestampInput,
  verifyTimestamp,
} from "../src/internal/sigstore/timestamp.js";
import { embeddedTrustedRoot, parseTrustedRoot, type TrustedRoot } from "../src/internal/sigstore/trusted-root.js";
import {
  conformanceAvailable,
  decodeDocument,
  inputBytes,
  loadFixture,
  loadFixtures,
  sigstoreCollateral,
  trustedRootBytes,
  vectorsTitle,
  type ConformanceFixture,
} from "./helpers/conformance.js";
import {
  ARTIFACT,
  b64,
  build,
  bytes,
  inclusionPath,
  leafHash,
  mutated,
  newLog,
  newSigner,
  pem,
  rootJson,
  rootOf,
  signP256,
  toJson,
  treeRoot,
  unb64,
  verify,
  type Built,
  type Signer,
  type TestLog,
} from "./helpers/keyed.js";
import { PUBLIC_SIGNING_KEY_PEM } from "../src/trust/signing-keys.js";

describe("keyHint and pinnedKeys", () => {
  it("hints the embedded signing key by base64 SHA-256 of its DER form", async () => {
    const der = new Uint8Array(createPublicKey(PUBLIC_SIGNING_KEY_PEM).export({ type: "spki", format: "der" }));
    const expected = createHash("sha256").update(der).digest("base64");
    expect(await keyHint(der)).toBe(expected);
    const keys = await pinnedKeys([PUBLIC_SIGNING_KEY_PEM]);
    expect(keys).toHaveLength(1);
    expect(keys[0].hint).toBe(expected);
    expect(await keyHint(keys[0].key)).toBe(expected);
  });

  it("rejects keys that are not ECDSA P-256", async () => {
    const p384 = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", p384.publicKey));
    await expect(keyHint(spki)).rejects.toThrow("ECDSA P-256");
    await expect(keyHint(p384.publicKey)).rejects.toThrow("ECDSA P-256");
    await expect(pinnedKeys([pem(spki)])).rejects.toThrow("ECDSA P-256");
    const ed = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    await expect(keyHint(ed.publicKey)).rejects.toThrow("ECDSA P-256");
    await expect(keyHint(p384.privateKey)).rejects.toThrow("ECDSA P-256");
    await expect(keyHint(bytes(0x30, 0x00))).rejects.toThrow("ECDSA P-256");
  });

  it("pins keys in order, rejecting a repeated key and PEM without a public key", async () => {
    const a = await newSigner();
    const b = await newSigner();
    const keys = await pinnedKeys([a.pem, b.pem]);
    expect(keys.map((k) => k.hint)).toEqual([a.hint, b.hint]);
    await expect(pinnedKeys([a.pem, b.pem + a.pem])).rejects.toThrow(`duplicate signing key ${a.hint}`);
    await expect(pinnedKeys(["not a pem"])).rejects.toThrow("no PUBLIC KEY block");
    await expect(pinnedKeys(["-----BEGIN PUBLIC KEY-----\nAAAA\n"])).rejects.toThrow("parsing signing key");
    await expect(pinnedKeys([])).rejects.toThrow("at least one signing key");
  });
});

// ---------------------------------------------------------------- key-signed bundles

describe("verifyKeyedBundle", () => {
  let signer: Signer;
  let other: Signer;
  let keys: PinnedKey[];
  let ecdsaLog: TestLog;
  let ed25519Log: TestLog;
  let strangerLog: TestLog;
  let root: TrustedRoot;
  let happy: Built;

  beforeAll(async () => {
    signer = await newSigner();
    other = await newSigner();
    keys = await pinnedKeys([signer.pem]);
    ecdsaLog = await newLog("ecdsa");
    ed25519Log = await newLog("ed25519", "ed.test.invalid");
    strangerLog = await newLog("ecdsa");
    root = await rootOf([ecdsaLog, ed25519Log]);
    happy = await build(signer, ecdsaLog);
  });

  it("accepts a bundle whose entry is in an ECDSA log and returns the hint", async () => {
    expect(await verify(root, happy.json, keys, happy.digest)).toBe(signer.hint);
  });

  it("accepts a bundle whose entry is in an Ed25519 log", async () => {
    const built = await build(signer, ed25519Log);
    expect(await verify(root, built.json, keys, built.digest)).toBe(signer.hint);
  });

  it("rejects a DSSE key id even when it equals the hint", async () => {
    const built = await build(signer, ecdsaLog, { keyid: signer.hint });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow(/key id must be empty/);
  });

  it("accepts eight entries proving leaves of an eight-leaf tree", async () => {
    const built = await build(signer, ecdsaLog, { entries: MAX_LOG_RECEIPTS });
    expect(await verify(root, built.json, keys, built.digest)).toBe(signer.hint);
  });

  it("accepts the artifact digest named by any subject", async () => {
    const digest = await sha256(ARTIFACT);
    const built = await build(signer, ecdsaLog, {
      statement: {
        _type: "https://in-toto.io/Statement/v1",
        subject: [
          { name: "other", digest: { sha256: toHex(await sha256(utf8("other"))) } },
          { name: "artifact", digest: { sha512: "", sha256: toHex(digest).toUpperCase() } },
        ],
        predicateType: "https://tinfoil.sh/predicate/test/v1",
        predicate: {},
      },
    });
    expect(await verify(root, built.json, keys, digest)).toBe(signer.hint);
  });

  it("rejects a hint that names no pinned key", async () => {
    const otherKeys = await pinnedKeys([other.pem]);
    await expect(verify(root, happy.json, otherKeys, happy.digest)).rejects.toThrow("untrusted approval signing key");
    const renamed = mutated(happy.json, (b) => (b.verificationMaterial.publicKey.hint = other.hint));
    await expect(verify(root, renamed, keys, happy.digest)).rejects.toThrow("untrusted approval signing key");
  });

  it("rejects a DSSE key id naming another key", async () => {
    const built = await build(signer, ecdsaLog, { keyid: other.hint });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow(/key id must be empty/);
  });

  it("rejects zero and nine entries", async () => {
    const none = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries = []));
    await expect(verify(root, none, keys, happy.digest)).rejects.toThrow("between 1 and 8");
    const nine = await build(signer, ecdsaLog, { entries: MAX_LOG_RECEIPTS + 1 });
    await expect(verify(root, nine.json, keys, nine.digest)).rejects.toThrow("between 1 and 8");
  });

  it("rejects an entry of another kind or version", async () => {
    const kind = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries[0].kindVersion.kind = "dsse"));
    await expect(verify(root, kind, keys, happy.digest)).rejects.toThrow("not hashedrekord 0.0.2");
    const version = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries[0].kindVersion.version = "0.0.1"));
    await expect(verify(root, version, keys, happy.digest)).rejects.toThrow("not hashedrekord 0.0.2");
    const bodyKind = await build(signer, ecdsaLog, { bodyKind: "dsse" });
    await expect(verify(root, bodyKind.json, keys, bodyKind.digest)).rejects.toThrow("body is dsse 0.0.2");
    const bodyVersion = await build(signer, ecdsaLog, { bodyVersion: "0.0.1" });
    await expect(verify(root, bodyVersion.json, keys, bodyVersion.digest)).rejects.toThrow("body is hashedrekord 0.0.1");
  });

  it("rejects an entry with an integration time", async () => {
    const json = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries[0].integratedTime = "1700000000"));
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("integration time");
  });

  it("rejects an entry with an inclusion promise", async () => {
    const json = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries[0].inclusionPromise = { signedEntryTimestamp: b64(utf8("x")) }));
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("inclusion promise");
  });

  it("rejects an entry without an inclusion proof", async () => {
    const json = mutated(happy.json, (b) => delete b.verificationMaterial.tlogEntries[0].inclusionProof);
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("no inclusion proof");
  });

  it("rejects RFC 3161 timestamps inside the bundle", async () => {
    const json = mutated(happy.json, (b) => (b.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [{ signedTimestamp: b64(utf8("x")) }] }));
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("no RFC 3161 timestamps");
  });

  it("cannot mint a bundle with no log entries", async () => {
    await expect(build(signer, ecdsaLog, { entries: 0 })).rejects.toThrow(/at least one log entry/);
  });

  it("rejects duplicate entries", async () => {
    const json = mutated(happy.json, (b) => b.verificationMaterial.tlogEntries.push(b.verificationMaterial.tlogEntries[0]));
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("duplicates");
  });

  it("rejects a body whose digest is not the digest of the signed message", async () => {
    const built = await build(signer, ecdsaLog, { bodyDigest: b64(await sha256(ARTIFACT)) });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("body digest");
  });

  it("rejects a body whose signature is not the DSSE signature", async () => {
    const built = await build(signer, ecdsaLog, { bodySignature: b64(await signP256(signer.pair.privateKey, utf8("other"))) });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("body signature");
  });

  it("rejects a body whose key is not the pinned key", async () => {
    const built = await build(signer, ecdsaLog, { bodyKey: b64(other.spki) });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("body public key");
  });

  it("rejects a body that is not in canonical form", async () => {
    const built = await build(signer, ecdsaLog, { bodyText: (c) => c.replace('"kind"', ' "kind"') });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("canonical form");
  });

  it("rejects a body with an extra member", async () => {
    const built = await build(signer, ecdsaLog, { bodyText: (c) => c.replace('"kind"', '"extra":1,"kind"') });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("unknown object member");
  });

  it("rejects an inclusion proof that does not reach the root", async () => {
    const built = await build(signer, ecdsaLog, { entries: 2 });
    const swapped = mutated(built.json, (b) => (b.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0] = b64(new Uint8Array(32))));
    await expect(verify(root, swapped, keys, built.digest)).rejects.toThrow("does not reach the root hash");
    const extraHash = mutated(built.json, (b) => b.verificationMaterial.tlogEntries[0].inclusionProof.hashes.push(b64(new Uint8Array(32))));
    await expect(verify(root, extraHash, keys, built.digest)).rejects.toThrow("expected 1");
  });

  it("rejects an inclusion proof whose root or size disagrees with the checkpoint", async () => {
    const rootHash = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries[0].inclusionProof.rootHash = b64(new Uint8Array(32))));
    await expect(verify(root, rootHash, keys, happy.digest)).rejects.toThrow("checkpoint's tree size and root hash");
    const size = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries[0].inclusionProof.treeSize = "2"));
    await expect(verify(root, size, keys, happy.digest)).rejects.toThrow("checkpoint's tree size and root hash");
  });

  it("rejects a checkpoint signed by a key other than the log's", async () => {
    const built = await build(signer, ecdsaLog, { checkpointSigner: strangerLog });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("not signed by the log");
  });

  it("rejects a checkpoint whose text was changed after signing", async () => {
    const json = mutated(happy.json, (b) => {
      const proof = b.verificationMaterial.tlogEntries[0].inclusionProof;
      proof.checkpoint.envelope = proof.checkpoint.envelope.replace("\n1\n", "\n2\n");
      proof.treeSize = "2";
    });
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("does not verify under the log key");
  });

  it("rejects a checkpoint for an origin other than the log's", async () => {
    const built = await build(signer, ecdsaLog, { checkpointOrigin: "elsewhere.test.invalid" });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("origin");
  });

  it("rejects an entry naming a log the trusted root does not list", async () => {
    const built = await build(signer, strangerLog);
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("does not list");
  });

  it("rejects a log without a base URL", async () => {
    const json = mutated(rootJson([ecdsaLog]), (r) => delete r.tlogs[0].baseUrl);
    const bare = await parseTrustedRoot(utf8(JSON.stringify(json)));
    await expect(verify(bare, happy.json, keys, happy.digest)).rejects.toThrow("not a URL");
  });

  it("rejects malformed checkpoint envelopes", async () => {
    const envelopeOf = (b: any): string => b.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope;
    const cases: [string, (e: string) => string][] = [
      ["no signature section", (e) => e.replace("\n\n", "\n")],
      ["unterminated signature", (e) => e.slice(0, -1)],
      ["wrong sentinel", (e) => e.replace("— ", "- ")],
      ["control character", (e) => e.replace("\n\n", "\t\n\n")],
      ["short signature", (e) => e.replace(/ [A-Za-z0-9+/=]+\n$/, " AAAA\n")],
      ["only witnesses", (e) => e.replace(`— ${ecdsaLog.origin} `, "— witness.test.invalid ")],
    ];
    for (const [name, change] of cases) {
      const json = mutated(happy.json, (b) => (b.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = change(envelopeOf(b))));
      await expect(verify(root, json, keys, happy.digest), name).rejects.toThrow();
    }
  });

  it("ignores signature lines of other signers", async () => {
    const json = mutated(happy.json, (b) => {
      const checkpoint = b.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint;
      checkpoint.envelope = checkpoint.envelope + `— witness.test.invalid ${b64(concat(bytes(1, 2, 3, 4), new Uint8Array(64)))}\n`;
    });
    expect(await verify(root, json, keys, happy.digest)).toBe(signer.hint);
  });

  it("rejects a DSSE signature that does not verify", async () => {
    const built = await build(signer, ecdsaLog, { signMessage: utf8("something else") });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("DSSE signature does not verify");
    const tampered = mutated(happy.json, (b) => (b.dsseEnvelope.payload = b64(concat(happy.payload, utf8(" ")))));
    await expect(verify(root, tampered, keys, happy.digest)).rejects.toThrow("DSSE signature does not verify");
  });

  it("rejects a statement whose subjects do not name the artifact digest", async () => {
    await expect(verify(root, happy.json, keys, await sha256(utf8("another artifact")))).rejects.toThrow("do not name the artifact digest");
    await expect(verify(root, happy.json, keys, happy.digest.subarray(1))).rejects.toThrow("not SHA-256");
    const built = await build(signer, ecdsaLog, { statement: { _type: "x", subject: [{ name: "a", digest: { sha256: "zz" } }] } });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("is not hex");
  });

  it.skipIf(!conformanceAvailable())(vectorsTitle("rejects a certificate-signed bundle"), async () => {
    const golden = decodeDocument(loadFixture("golden/golden-happy.json"));
    const bundle = sigstoreCollateral(golden).find((c) => c.id === "sigstore-code")!.data.sigstore_bundle;
    await expect(verify(root, bundle, keys, happy.digest)).rejects.toThrow("not a certificate");
  });

  it("rejects a payload type other than in-toto", async () => {
    const json = mutated(happy.json, (b) => (b.dsseEnvelope.payloadType = "application/json"));
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("unsupported DSSE payload type");
  });
});

const approvalFixtures = conformanceAvailable() ? loadFixtures("approval-bundle") : [];

describe.skipIf(!conformanceAvailable())(vectorsTitle("verifyKeyedBundle"), () => {
  for (const fixture of approvalFixtures) {
    const { expected } = fixture;
    it(`${fixture.id}: ${expected.accepted ? "accepts" : "rejects"}`, async () => {
      const { signing_keys_pem: pems, artifact_digest_hex: hex } = fixture.input;
      if (pems === undefined || hex === undefined) throw new Error(`${fixture.id}: input lacks signing_keys_pem or artifact_digest_hex`);
      const rootBytes = trustedRootBytes(fixture);
      const root = rootBytes === undefined ? await embeddedTrustedRoot() : await parseTrustedRoot(rootBytes);
      const digest = new Uint8Array(Buffer.from(hex, "hex"));
      // The vector's verdict covers parsing as well as verification, so both run under the expectation.
      const run = async (): Promise<string> =>
        verifyKeyedBundle(root, parseBundle(strictParse(inputBytes(fixture, "bundle_json_b64"))), await pinnedKeys(pems), digest);
      if (expected.accepted) {
        expect(await run()).toBe(expected.signing_key_hint);
      } else {
        await expect(run()).rejects.toThrow();
      }
    });
  }
});

describe("verifyMerkleInclusion", () => {
  it("verifies every leaf of a five-leaf tree and rejects wrong indexes", async () => {
    const leaves = ["a", "b", "c", "d", "e"].map((s) => utf8(s));
    const root = await treeRoot(leaves);
    for (let i = 0; i < leaves.length; i++) {
      const path = await inclusionPath(leaves, i);
      await verifyMerkleInclusion(await leafHash(leaves[i]), BigInt(i), 5n, path, root);
      const wrong = (i + 1) % leaves.length;
      await expect(verifyMerkleInclusion(await leafHash(leaves[wrong]), BigInt(i), 5n, path, root)).rejects.toThrow("does not reach");
    }
    await expect(verifyMerkleInclusion(await leafHash(leaves[0]), 5n, 5n, [], root)).rejects.toThrow("outside a tree");
    await expect(verifyMerkleInclusion(await leafHash(leaves[0]), 0n, 5n, [], root)).rejects.toThrow("expected 3");
  });
});

// ---------------------------------------------------------------- timestamps

interface ProductionFixture {
  readonly input: string;
  readonly genTime: string;
  readonly response: string;
}

const production = JSON.parse(readFileSync(new URL("./fixtures/sigstore/rfc3161-production.json", import.meta.url), "utf8")) as ProductionFixture;

/** The response, the bytes it timestamps, and the trusted root of a v3-verify-timestamp vector. */
interface TimestampCase {
  readonly fixture: ConformanceFixture;
  readonly response: Uint8Array;
  readonly input: Uint8Array;
  readonly rootJson: unknown;
  readonly root: TrustedRoot;
}

async function timestampCase(fixture: ConformanceFixture): Promise<TimestampCase> {
  const rootBytes = trustedRootBytes(fixture);
  if (rootBytes === undefined) throw new Error(`${fixture.id}: input has no sigstore_trusted_root_json_b64`);
  return {
    fixture,
    response: inputBytes(fixture, "timestamp_response_b64"),
    input: inputBytes(fixture, "timestamp_input_b64"),
    rootJson: JSON.parse(new TextDecoder().decode(rootBytes)),
    root: await parseTrustedRoot(rootBytes),
  };
}

/** The response with its PKIStatus set to grantedWithMods. */
function withMods(response: Uint8Array): Uint8Array {
  const out = new Uint8Array(response);
  const status = [0x30, 0x03, 0x02, 0x01, 0x00];
  for (let i = 0; i + status.length <= out.length; i++) {
    if (status.every((b, j) => out[i + j] === b)) {
      out[i + 4] = 0x01;
      return out;
    }
  }
  throw new Error("status not found");
}

const timestampFixtures = conformanceAvailable() ? loadFixtures("rfc3161") : [];

describe("timestampInput and endorsementReference", () => {
  it("prefixes the domain to the canonical core", () => {
    expect(new TextDecoder().decode(timestampInput("d", toJson({ b: 1, a: [true, null] })))).toBe('d{"a":[true,null],"b":1}');
  });

  it.skipIf(!conformanceAvailable())(vectorsTitle("reproduces the input the rfc3161 vectors timestamp"), () => {
    // The vectors' input is a domain followed by a canonical JSON core.
    const text = new TextDecoder().decode(inputBytes(timestampFixtures.find((f) => f.id === "granted-p256")!, "timestamp_input_b64"));
    const at = text.indexOf("{");
    expect(at).toBeGreaterThan(0);
    expect(new TextDecoder().decode(timestampInput(text.slice(0, at), toJson(JSON.parse(text.slice(at)))))).toBe(text);
  });

  it("references the SHA-256 of the pre-authentication encoding", async () => {
    const payload = utf8('{"x":1}');
    const pae = Buffer.concat([Buffer.from("DSSEv1 28 application/vnd.in-toto+json 7 "), payload]);
    expect(preAuthEncoding(IN_TOTO_PAYLOAD_TYPE, payload)).toEqual(new Uint8Array(pae));
    expect(await endorsementReference(payload)).toBe("sha256:" + createHash("sha256").update(pae).digest("hex"));
    expect(preAuthEncoding("ü", bytes())).toEqual(utf8("DSSEv1 2 ü 0 "));
  });
});

describe("verifyTimestamp", () => {
  it("accepts a production response under the embedded trusted root", async () => {
    const at = await verifyTimestamp(await embeddedTrustedRoot(), unb64(production.response), utf8(production.input));
    expect(at).toEqual(new Date(production.genTime));
    await expect(verifyTimestamp(await embeddedTrustedRoot(), unb64(production.response), utf8("other input"))).rejects.toThrow("does not match the input");
  });
});

/**
 * The reason each reject vector must fail for. A vector that rejects for
 * another reason would pass a bare rejection check while leaving the rule it
 * exercises untested; a new vector must be added here.
 */
const TIMESTAMP_REJECTIONS: Readonly<Record<string, RegExp>> = {
  "after-window": /authority 0: not valid at/,
  "before-window": /authority 0: not valid at/,
  "eku-not-critical": /extended key usage must be critical/,
  "granted-with-mods": /not granted \(status 1\)/,
  "imprint-mismatch": /does not match the input/,
  "no-eku": /has no extended key usage/,
  "signer-expired": /TSA signer\) is not valid at/,
  "status-rejected": /not granted \(status 2\)/,
  "tampered-gentime": /signed attributes do not commit to the TSTInfo/,
  "trailing-bytes": /trailing bytes after the element/,
  "unknown-authority": /authority 0: the token's signer is not the authority's signing certificate/,
  "wrong-policy": /unexpected timestamp policy/,
};

describe.skipIf(!conformanceAvailable())(vectorsTitle("verifyTimestamp"), () => {
  for (const fixture of timestampFixtures) {
    const { expected } = fixture;
    it(`${fixture.id}: ${expected.accepted ? `accepts at ${expected.timestamp}` : "rejects"}`, async () => {
      const c = await timestampCase(fixture);
      if (expected.accepted) {
        expect(await verifyTimestamp(c.root, c.response, c.input)).toEqual(new Date(expected.timestamp as string));
      } else {
        const reason = TIMESTAMP_REJECTIONS[fixture.id];
        expect(reason, `no expected reason for vector ${fixture.id}`).toBeDefined();
        await expect(verifyTimestamp(c.root, c.response, c.input)).rejects.toThrow(reason);
      }
    });
  }

  // The cases below start from the granted-p256 vector and alter the response,
  // the input or the root in ways no vector does.
  let granted: TimestampCase;
  let genTime: Date;

  beforeAll(async () => {
    granted = await timestampCase(timestampFixtures.find((f) => f.id === "granted-p256")!);
    genTime = new Date(granted.fixture.expected.timestamp as string);
  });

  /** The granted-p256 root with every authority's validity window replaced. */
  function windowed(window: { start: string; end?: string }): Promise<TrustedRoot> {
    const json = mutated(granted.rootJson, (r: any) => r.timestampAuthorities.forEach((a: any) => (a.validFor = window)));
    return parseTrustedRoot(utf8(JSON.stringify(json)));
  }

  it("parses what a granted response states", () => {
    const ts = parseTimestampResponse(granted.response);
    expect(ts.status).toBe(STATUS_GRANTED);
    expect(ts.policy).toBe(SIGSTORE_TIMESTAMP_POLICY);
    expect(ts.genTime).toEqual(genTime);
    expect(ts.imprintAlgorithm).toBe("2.16.840.1.101.3.4.2.1");
    expect(toHex(ts.imprint)).toBe(createHash("sha256").update(granted.input).digest("hex"));
    expect(ts.signerSerial).toBeGreaterThan(0n);
    expect(() => parseTimestampResponse(withMods(granted.response))).toThrow(/not granted \(status 1\)/);
  });

  it("rejects a grant with modifications", async () => {
    await expect(verifyTimestamp(granted.root, withMods(granted.response), granted.input)).rejects.toThrow(/not granted/);
  });

  it("rejects an input other than the one timestamped", async () => {
    await expect(verifyTimestamp(granted.root, granted.response, concat(granted.input, utf8("x")))).rejects.toThrow("does not match the input");
  });

  it("rejects a root listing no authority", async () => {
    const empty = await parseTrustedRoot(utf8(JSON.stringify(mutated(granted.rootJson, (r: any) => (r.timestampAuthorities = [])))));
    await expect(verifyTimestamp(empty, granted.response, granted.input)).rejects.toThrow("no trusted timestamp authority");
  });

  it("rejects a time outside the authority's window and accepts one on its edges", async () => {
    const iso = genTime.toISOString();
    const second = new Date(genTime.getTime() + 1000).toISOString();
    const late = await windowed({ start: second });
    await expect(verifyTimestamp(late, granted.response, granted.input)).rejects.toThrow(`not valid at ${iso}`);
    const early = await windowed({ start: "2000-01-01T00:00:00Z", end: new Date(genTime.getTime() - 1000).toISOString() });
    await expect(verifyTimestamp(early, granted.response, granted.input)).rejects.toThrow("not valid at");
    const exact = await windowed({ start: iso, end: iso });
    expect(await verifyTimestamp(exact, granted.response, granted.input)).toEqual(genTime);
  });

  it("rejects inputs and responses outside the size bounds", async () => {
    await expect(verifyTimestamp(granted.root, granted.response, new Uint8Array(MAX_STATEMENT_SIZE + 1))).rejects.toThrow("input size");
    await expect(verifyTimestamp(granted.root, granted.response, new Uint8Array(0))).rejects.toThrow("input size");
    await expect(verifyTimestamp(granted.root, new Uint8Array(MAX_TIMESTAMP_SIZE + 1), granted.input)).rejects.toThrow("response size");
    await expect(verifyTimestamp(granted.root, new Uint8Array(0), granted.input)).rejects.toThrow("response size");
  });

  it("rejects malformed and tampered responses", async () => {
    const { root, response, input } = granted;
    await expect(verifyTimestamp(root, response.subarray(0, response.length - 1), input)).rejects.toThrow("timestamp response:");
    await expect(verifyTimestamp(root, concat(response, bytes(0)), input)).rejects.toThrow("timestamp response:");
    // genTime is a GeneralizedTime, YYYYMMDDHHMMSSZ; bump its seconds digit.
    const stated = genTime.toISOString().replace(/[-:T]|\.\d+/g, "");
    const tampered = mutated(response, (r: Uint8Array) => {
      const i = Buffer.from(r).indexOf(stated);
      expect(i).toBeGreaterThan(0);
      r[i + 13] = r[i + 13] === 0x39 ? 0x30 : r[i + 13] + 1;
    });
    await expect(verifyTimestamp(root, tampered, input)).rejects.toThrow("do not commit to the TSTInfo");
    const signature = mutated(response, (r: Uint8Array) => (r[r.length - 1] ^= 0x01));
    await expect(verifyTimestamp(root, signature, input)).rejects.toThrow();
  });
});
