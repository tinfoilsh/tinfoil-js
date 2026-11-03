/**
 * Tests for the key-signed half of the Sigstore module: key hints and pinned
 * keys, key-signed bundle verification (keyed.ts), and RFC 3161 timestamps
 * with the canonical statement input (timestamp.ts).
 *
 * Key-signed bundles are built here with WebCrypto: a fresh signing key, a
 * transparency log key (ECDSA or Ed25519) that signs checkpoints over small
 * Merkle trees, and a trusted root listing that log. Timestamp responses
 * come from fixtures/sigstore/rfc3161-tokens.json, minted by the generator
 * next to it over synthetic authorities, and rfc3161-production.json, one
 * response from the production authority that verifies under the embedded
 * trusted root.
 */
import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { concat, sha256, toHex, utf8 } from "../../src/v3/internal/bytes.js";
import { strictParse, type JsonValue } from "../../src/v3/internal/json/index.js";
import { BUNDLE_MEDIA_TYPE, IN_TOTO_PAYLOAD_TYPE, parseBundle } from "../../src/v3/internal/sigstore/bundle.js";
import {
  keyHint,
  MAX_LOG_RECEIPTS,
  pinnedKeys,
  verifyKeyedBundle,
  verifyMerkleInclusion,
  type PinnedKey,
} from "../../src/v3/internal/sigstore/keyed.js";
import {
  endorsementReference,
  MAX_STATEMENT_SIZE,
  MAX_TIMESTAMP_SIZE,
  parseTimestampResponse,
  preAuthEncoding,
  SIGSTORE_TIMESTAMP_POLICY,
  STATUS_GRANTED,
  STATUS_GRANTED_WITH_MODS,
  timestampInput,
  verifyTimestamp,
} from "../../src/v3/internal/sigstore/timestamp.js";
import { embeddedTrustedRoot, parseTrustedRoot, TRUSTED_ROOT_MEDIA_TYPE, type TrustedRoot } from "../../src/v3/internal/sigstore/trusted-root.js";
import { PUBLIC_SIGNING_KEY_PEM } from "../../src/v3/trust/signing-keys.js";

// ---------------------------------------------------------------- helpers

const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));
const toJson = (value: unknown): JsonValue => strictParse(utf8(JSON.stringify(value)));
const bytes = (...b: number[]): Uint8Array => new Uint8Array(b);

const P256: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };

/** A copy of a plain JSON value with `mutate` applied. */
function mutated<T>(value: T, mutate: (v: any) => void): T {
  const copy = structuredClone(value) as T;
  mutate(copy);
  return copy;
}

/** A DER ECDSA signature from WebCrypto's fixed-width r‖s form. */
function derSignature(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let m = b.subarray(i);
    if (m[0] & 0x80) m = concat(bytes(0), m);
    return concat(bytes(0x02, m.length), m);
  };
  const half = raw.length / 2;
  const body = concat(int(raw.subarray(0, half)), int(raw.subarray(half)));
  return concat(bytes(0x30, body.length), body);
}

function pem(spki: Uint8Array): string {
  const lines = b64(spki).match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

interface Signer {
  readonly pair: CryptoKeyPair;
  readonly spki: Uint8Array;
  readonly hint: string;
  readonly pem: string;
}

async function newSigner(): Promise<Signer> {
  const pair = await crypto.subtle.generateKey(P256, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  return { pair, spki, hint: await keyHint(spki), pem: pem(spki) };
}

async function signP256(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return derSignature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data as Uint8Array<ArrayBuffer>)));
}

/** A transparency log: its key, origin, and the id its entries carry. */
interface TestLog {
  readonly kind: "ecdsa" | "ed25519";
  readonly origin: string;
  readonly pair: CryptoKeyPair;
  readonly spki: Uint8Array;
  readonly logId: Uint8Array;
}

async function newLog(kind: TestLog["kind"], origin = "log.test.invalid"): Promise<TestLog> {
  if (kind === "ecdsa") {
    const pair = await crypto.subtle.generateKey(P256, true, ["sign", "verify"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    return { kind, origin, pair, spki, logId: await sha256(spki) };
  }
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  // The id of an Ed25519 log hashes its origin, a newline, 0x01 and the raw key.
  const logId = await sha256(concat(utf8(origin), bytes(0x0a, 0x01), spki.subarray(spki.length - 32)));
  return { kind, origin, pair, spki, logId };
}

/** A signature line of a signed note, by `log`, under the given name. */
async function signNote(log: TestLog, text: string, name = log.origin): Promise<string> {
  const data = utf8(text);
  const sig =
    log.kind === "ecdsa"
      ? await signP256(log.pair.privateKey, data)
      : new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, log.pair.privateKey, data as Uint8Array<ArrayBuffer>));
  return `— ${name} ${b64(concat(log.logId.subarray(0, 4), sig))}\n`;
}

interface AuthorityJson {
  readonly certificates: readonly string[];
  readonly start: string;
  readonly end?: string;
}

function rootJson(logs: readonly TestLog[], authorities: readonly AuthorityJson[] = []): unknown {
  return {
    mediaType: TRUSTED_ROOT_MEDIA_TYPE,
    tlogs: logs.map((l) => ({
      baseUrl: `https://${l.origin}`,
      hashAlgorithm: "SHA2_256",
      publicKey: {
        rawBytes: b64(l.spki),
        keyDetails: l.kind === "ecdsa" ? "PKIX_ECDSA_P256_SHA_256" : "PKIX_ED25519",
        validFor: { start: "2025-01-01T00:00:00Z" },
      },
      logId: { keyId: b64(l.logId) },
    })),
    certificateAuthorities: [],
    ctlogs: [],
    timestampAuthorities: authorities.map((a) => ({
      subject: { organization: "test", commonName: "test timestamp authority" },
      uri: "https://tsa.test.invalid",
      certChain: { certificates: a.certificates.map((rawBytes) => ({ rawBytes })) },
      validFor: { start: a.start, ...(a.end === undefined ? {} : { end: a.end }) },
    })),
  };
}

function rootOf(logs: readonly TestLog[], authorities: readonly AuthorityJson[] = []): Promise<TrustedRoot> {
  return parseTrustedRoot(utf8(JSON.stringify(rootJson(logs, authorities))));
}

// RFC 6962 trees over the leaves of a test log.
const leafHash = (leaf: Uint8Array): Promise<Uint8Array> => sha256(concat(bytes(0x00), leaf));
const nodeHash = (l: Uint8Array, r: Uint8Array): Promise<Uint8Array> => sha256(concat(bytes(0x01), l, r));

/** The largest power of two less than n. */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

async function treeRoot(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 1) return leafHash(leaves[0]);
  const k = splitPoint(leaves.length);
  return nodeHash(await treeRoot(leaves.slice(0, k)), await treeRoot(leaves.slice(k)));
}

async function inclusionPath(leaves: readonly Uint8Array[], index: number): Promise<Uint8Array[]> {
  if (leaves.length === 1) return [];
  const k = splitPoint(leaves.length);
  return index < k
    ? [...(await inclusionPath(leaves.slice(0, k), index)), await treeRoot(leaves.slice(k))]
    : [...(await inclusionPath(leaves.slice(k), index - k)), await treeRoot(leaves.slice(0, k))];
}

const ARTIFACT = utf8("the approved artifact bytes");

interface BuildOptions {
  readonly statement?: unknown;
  readonly keyid?: string;
  /** Sign these bytes instead of the envelope's pre-authentication encoding. */
  readonly signMessage?: Uint8Array;
  readonly bodyDigest?: string;
  readonly bodySignature?: string;
  readonly bodyKey?: string;
  readonly bodyKind?: string;
  readonly bodyVersion?: string;
  /** Rewrites the body text the log signs over, to make it non-canonical. */
  readonly bodyText?: (canonical: string) => string;
  /** Entries to include; entry i proves the leaf at index i of a tree of this many copies of the body. */
  readonly entries?: number;
  /** The log whose key signs the checkpoint, when not the entry's log. */
  readonly checkpointSigner?: TestLog;
  /** The origin written in the checkpoint text, when not the log's. */
  readonly checkpointOrigin?: string;
}

interface Built {
  readonly json: unknown;
  readonly payload: Uint8Array;
  readonly digest: Uint8Array;
}

/** A key-signed bundle over a statement naming the artifact, with entries in `log`. */
async function build(signer: Signer, log: TestLog, opts: BuildOptions = {}): Promise<Built> {
  const digest = await sha256(ARTIFACT);
  const statement = opts.statement ?? {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "artifact", digest: { sha256: toHex(digest) } }],
    predicateType: "https://tinfoil.sh/predicate/test/v1",
    predicate: { note: "built in test" },
  };
  const payload = utf8(JSON.stringify(statement));
  const pae = preAuthEncoding(IN_TOTO_PAYLOAD_TYPE, payload);
  const sig = await signP256(signer.pair.privateKey, opts.signMessage ?? pae);
  const canonical = JSON.stringify({
    apiVersion: opts.bodyVersion ?? "0.0.2",
    kind: opts.bodyKind ?? "hashedrekord",
    spec: {
      hashedRekordV002: {
        data: { algorithm: "SHA2_256", digest: opts.bodyDigest ?? b64(await sha256(pae)) },
        signature: {
          content: opts.bodySignature ?? b64(sig),
          verifier: { keyDetails: "PKIX_ECDSA_P256_SHA_256", publicKey: { rawBytes: opts.bodyKey ?? b64(signer.spki) } },
        },
      },
    },
  });
  const body = utf8(opts.bodyText === undefined ? canonical : opts.bodyText(canonical));
  const count = opts.entries ?? 1;
  const leaves = Array.from({ length: count }, () => body);
  const root = await treeRoot(leaves);
  const text = `${opts.checkpointOrigin ?? log.origin}\n${count}\n${b64(root)}\n`;
  const envelope = text + "\n" + (await signNote(opts.checkpointSigner ?? log, text, log.origin));
  const tlogEntries = [];
  for (let i = 0; i < count; i++) {
    tlogEntries.push({
      logIndex: String(i),
      logId: { keyId: b64(log.logId) },
      kindVersion: { kind: "hashedrekord", version: "0.0.2" },
      canonicalizedBody: b64(body),
      inclusionProof: {
        logIndex: String(i),
        rootHash: b64(root),
        treeSize: String(count),
        hashes: (await inclusionPath(leaves, i)).map(b64),
        checkpoint: { envelope },
      },
    });
  }
  return {
    json: {
      mediaType: BUNDLE_MEDIA_TYPE,
      verificationMaterial: { publicKey: { hint: signer.hint }, tlogEntries },
      dsseEnvelope: {
        payload: b64(payload),
        payloadType: IN_TOTO_PAYLOAD_TYPE,
        signatures: [{ sig: b64(sig), ...(opts.keyid === undefined ? {} : { keyid: opts.keyid }) }],
      },
    },
    payload,
    digest,
  };
}

function verify(root: TrustedRoot, json: unknown, keys: readonly PinnedKey[], digest: Uint8Array): Promise<string> {
  return verifyKeyedBundle(root, parseBundle(toJson(json)), keys, digest);
}

// ---------------------------------------------------------------- keys

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

  it("deduplicates pinned keys by hint and rejects PEM without a public key", async () => {
    const a = await newSigner();
    const b = await newSigner();
    const keys = await pinnedKeys([a.pem, b.pem + a.pem]);
    expect(keys.map((k) => k.hint)).toEqual([a.hint, b.hint]);
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

  it("accepts a DSSE key id equal to the hint", async () => {
    const built = await build(signer, ecdsaLog, { keyid: signer.hint });
    expect(await verify(root, built.json, keys, built.digest)).toBe(signer.hint);
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

  it("rejects a DSSE key id that disagrees with the hint", async () => {
    const built = await build(signer, ecdsaLog, { keyid: other.hint });
    await expect(verify(root, built.json, keys, built.digest)).rejects.toThrow("DSSE key id disagrees");
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

  it("rejects a certificate-signed bundle", async () => {
    const fixture = JSON.parse(readFileSync(new URL("./fixtures/sigstore/golden-happy.json", import.meta.url), "utf8"));
    const bundle = fixture.collateral.find((c: any) => c.id === "sigstore-code").data.sigstore_bundle;
    await expect(verify(root, bundle, keys, happy.digest)).rejects.toThrow("not a certificate");
  });

  it("rejects a payload type other than in-toto", async () => {
    const json = mutated(happy.json, (b) => (b.dsseEnvelope.payloadType = "application/json"));
    await expect(verify(root, json, keys, happy.digest)).rejects.toThrow("unsupported DSSE payload type");
  });
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

interface AuthorityFixture {
  readonly note: string;
  readonly curve: string;
  readonly certificates: readonly string[];
  readonly notBefore: string;
  readonly notAfter: string;
}

interface TokenFixture {
  readonly note: string;
  readonly authority: string;
  readonly status: number;
  readonly policy?: string;
  readonly hashAlgorithm?: string;
  readonly genTime?: string;
  readonly response: string;
}

interface TokensFixture {
  readonly note: string;
  readonly domain: string;
  readonly core: unknown;
  readonly input: string;
  readonly authorities: Record<string, AuthorityFixture>;
  readonly tokens: Record<string, TokenFixture>;
}

interface ProductionFixture {
  readonly input: string;
  readonly genTime: string;
  readonly response: string;
}

const tokens = JSON.parse(readFileSync(new URL("./fixtures/sigstore/rfc3161-tokens.json", import.meta.url), "utf8")) as TokensFixture;
const production = JSON.parse(readFileSync(new URL("./fixtures/sigstore/rfc3161-production.json", import.meta.url), "utf8")) as ProductionFixture;
const input = unb64(tokens.input);
const token = (id: string): Uint8Array => unb64(tokens.tokens[id].response);

const WINDOW = { start: "2026-01-01T00:00:00Z" };

function authorityRoot(names: readonly string[], window: { start: string; end?: string } = WINDOW): Promise<TrustedRoot> {
  return rootOf(
    [],
    names.map((name) => ({ certificates: tokens.authorities[name].certificates, ...window })),
  );
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

describe("timestampInput and endorsementReference", () => {
  it("prefixes the domain to the canonical core", () => {
    expect(timestampInput(tokens.domain, toJson(tokens.core))).toEqual(input);
    expect(new TextDecoder().decode(timestampInput("d", toJson({ b: 1, a: [true, null] })))).toBe('d{"a":[true,null],"b":1}');
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
  let p256: TrustedRoot;
  let p384: TrustedRoot;
  let both: TrustedRoot;

  beforeAll(async () => {
    p256 = await authorityRoot(["p256"]);
    p384 = await authorityRoot(["p384"]);
    both = await authorityRoot(["p384", "p256"]);
  });

  it("parses what a granted response states", () => {
    const ts = parseTimestampResponse(token("granted-p256"));
    expect(ts.status).toBe(STATUS_GRANTED);
    expect(ts.policy).toBe(SIGSTORE_TIMESTAMP_POLICY);
    expect(ts.genTime.toISOString()).toBe("2026-06-15T12:00:00.000Z");
    expect(ts.imprintAlgorithm).toBe("2.16.840.1.101.3.4.2.1");
    expect(toHex(ts.imprint)).toBe(createHash("sha256").update(input).digest("hex"));
    expect(ts.signerSerial).toBe(2n);
    expect(parseTimestampResponse(withMods(token("granted-p256"))).status).toBe(STATUS_GRANTED_WITH_MODS);
  });

  it("accepts granted responses from P-256 and P-384 authorities", async () => {
    const genTime = new Date(tokens.tokens["granted-p256"].genTime!);
    expect(await verifyTimestamp(p256, token("granted-p256"), input)).toEqual(genTime);
    expect(await verifyTimestamp(p256, token("granted-p256-no-cert"), input)).toEqual(genTime);
    expect(await verifyTimestamp(p384, token("granted-p384"), input)).toEqual(genTime);
    expect(await verifyTimestamp(p384, token("granted-p384-sha384"), input)).toEqual(genTime);
    expect(await verifyTimestamp(both, token("granted-p256"), input)).toEqual(genTime);
    expect(await verifyTimestamp(p256, withMods(token("granted-p256")), input)).toEqual(genTime);
  });

  it("accepts a production response under the embedded trusted root", async () => {
    const at = await verifyTimestamp(await embeddedTrustedRoot(), unb64(production.response), utf8(production.input));
    expect(at).toEqual(new Date(production.genTime));
    await expect(verifyTimestamp(await embeddedTrustedRoot(), unb64(production.response), input)).rejects.toThrow("does not match the input");
  });

  it("rejects a response that was not granted", async () => {
    await expect(verifyTimestamp(p256, token("rejected"), input)).rejects.toThrow("not granted (status 2)");
  });

  it("rejects an imprint that is not SHA-256 of the input", async () => {
    await expect(verifyTimestamp(p256, token("granted-p256"), concat(input, utf8("x")))).rejects.toThrow("does not match the input");
    await expect(verifyTimestamp(p256, token("sha384-imprint"), input)).rejects.toThrow("does not match the input");
  });

  it("rejects a policy other than the Sigstore one", async () => {
    await expect(verifyTimestamp(p256, token("other-policy"), input)).rejects.toThrow("unexpected timestamp policy 1.2.3.4");
  });

  it("rejects a response no listed authority signed", async () => {
    await expect(verifyTimestamp(p384, token("granted-p256"), input)).rejects.toThrow("no trusted timestamp authority");
    await expect(verifyTimestamp(await authorityRoot([]), token("granted-p256"), input)).rejects.toThrow("no trusted timestamp authority");
  });

  it("rejects a time outside the authority's window", async () => {
    const late = await authorityRoot(["p256"], { start: "2026-06-15T12:00:01Z" });
    await expect(verifyTimestamp(late, token("granted-p256"), input)).rejects.toThrow("not valid at 2026-06-15T12:00:00.000Z");
    const early = await authorityRoot(["p256"], { start: "2026-01-01T00:00:00Z", end: "2026-06-15T11:59:59Z" });
    await expect(verifyTimestamp(early, token("granted-p256"), input)).rejects.toThrow("not valid at");
    const exact = await authorityRoot(["p256"], { start: "2026-06-15T12:00:00Z", end: "2026-06-15T12:00:00Z" });
    expect(await verifyTimestamp(exact, token("granted-p256"), input)).toEqual(new Date("2026-06-15T12:00:00Z"));
  });

  it("rejects a time at which the signing certificate was not valid", async () => {
    await expect(verifyTimestamp(p256, token("after-signer-expiry"), input)).rejects.toThrow("is not valid at 2027-06-15T12:00:00.000Z");
  });

  it("rejects a signing certificate not restricted to timestamping", async () => {
    const lax = await authorityRoot(["lax-eku"]);
    await expect(verifyTimestamp(lax, token("lax-eku"), input)).rejects.toThrow("extended key usage must be critical");
    const none = await authorityRoot(["no-eku"]);
    await expect(verifyTimestamp(none, token("no-eku"), input)).rejects.toThrow("no extended key usage");
  });

  it("rejects inputs and responses outside the size bounds", async () => {
    await expect(verifyTimestamp(p256, token("granted-p256"), new Uint8Array(MAX_STATEMENT_SIZE + 1))).rejects.toThrow("input size");
    await expect(verifyTimestamp(p256, token("granted-p256"), new Uint8Array(0))).rejects.toThrow("input size");
    await expect(verifyTimestamp(p256, new Uint8Array(MAX_TIMESTAMP_SIZE + 1), input)).rejects.toThrow("response size");
    await expect(verifyTimestamp(p256, new Uint8Array(0), input)).rejects.toThrow("response size");
  });

  it("rejects malformed and tampered responses", async () => {
    const granted = token("granted-p256");
    await expect(verifyTimestamp(p256, granted.subarray(0, granted.length - 1), input)).rejects.toThrow("timestamp response:");
    await expect(verifyTimestamp(p256, concat(granted, bytes(0)), input)).rejects.toThrow("timestamp response:");
    const genTime = mutated(granted, (r: Uint8Array) => {
      const i = Buffer.from(r).indexOf("20260615120000Z");
      expect(i).toBeGreaterThan(0);
      r[i + 13] = 0x31;
    });
    await expect(verifyTimestamp(p256, genTime, input)).rejects.toThrow("do not commit to the TSTInfo");
    const signature = mutated(granted, (r: Uint8Array) => (r[r.length - 1] ^= 0x01));
    await expect(verifyTimestamp(p256, signature, input)).rejects.toThrow();
  });
});
