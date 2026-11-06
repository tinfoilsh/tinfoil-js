/**
 * Key-signed bundle verification for approvals signed with a pinned key:
 * no certificate, a public-key hint, between one and eight hashedrekord
 * 0.0.2 log entries each with an inclusion proof and no promise, no
 * integration times, and no RFC 3161 timestamps inside the bundle.
 *
 * Each log entry's body must be the canonical hashedrekord record the log
 * would have built from this envelope and key: the digest of the signed
 * message, the DSSE signature, and the pinned key's DER form. Its inclusion
 * proof must reach the root of a checkpoint (a signed note) that the entry's
 * log signed for its own origin. Nothing in a key-signed bundle states a
 * time, so log keys are not checked against their validity windows here; the
 * approval's own signed timestamp establishes when it was made.
 */
import { concat, sha256, toHex, utf8 } from "../bytes.js";
import { decodeBase64 } from "../canonical.js";
import { arr, object, str, struct } from "../json/decode.js";
import { canonicalize, JsonNumber, strictParse, type JsonValue } from "../json/index.js";
import { bytesEqual, expectSequence, isUniversal } from "../x509/certificate.js";
import { bitString, decode, DerError, ecdsaSignatureToRaw, oid, pemBlocks, TAG } from "../x509/der.js";
import { IN_TOTO_PAYLOAD_TYPE, type Bundle, type TlogEntry } from "./bundle.js";
import { MAX_TIMESTAMP_SIZE, preAuthEncoding } from "./timestamp.js";
import type { KeyedAuthority, TrustedRoot } from "./trusted-root.js";

export const MAX_LOG_RECEIPTS = 8;

/** The log entry kind and version a key-signed approval must carry. */
export const HASHEDREKORD_KIND = "hashedrekord";
export const HASHEDREKORD_VERSION = "0.0.2";

/** A pinned P-256 verification key and the hint that names it. */
export interface PinnedKey {
  readonly hint: string;
  readonly key: CryptoKey;
}

const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_P256 = "1.2.840.10045.3.1.7";
const P256: EcKeyImportParams = { name: "ECDSA", namedCurve: "P-256" };

/** base64 SHA-256 of the DER public key: the hint a bundle names a key by. */
export async function keyHint(spki: Uint8Array): Promise<string>;
export async function keyHint(key: CryptoKey): Promise<string>;
export async function keyHint(key: Uint8Array | CryptoKey): Promise<string> {
  const imported = key instanceof Uint8Array ? await importP256(key) : key;
  return toBase64(await sha256(await exportP256(imported)));
}

/** Imports PEM-encoded P-256 public keys as pinned keys; a key that repeats rejects. */
export async function pinnedKeys(pems: readonly string[]): Promise<PinnedKey[]> {
  const out: PinnedKey[] = [];
  const seen = new Set<string>();
  for (const pem of pems) {
    let blocks: Uint8Array[];
    try {
      blocks = pemBlocks(pem, "PUBLIC KEY");
    } catch (err) {
      throw new Error(`parsing signing key: ${message(err)}`);
    }
    if (blocks.length === 0) throw new Error("signing key PEM has no PUBLIC KEY block");
    for (const spki of blocks) {
      const key = await importP256(spki);
      const hint = await keyHint(key);
      if (seen.has(hint)) throw new Error(`duplicate signing key ${hint}`);
      seen.add(hint);
      out.push({ hint, key });
    }
  }
  if (out.length === 0) throw new Error("at least one signing key is required");
  return out;
}

/**
 * Verifies a key-signed DSSE bundle: the layout above, the key hint naming
 * one of `keys` with an empty DSSE key id, every log entry's
 * body consistent with the envelope and its inclusion proof and checkpoint
 * valid for a log in `root`, and the DSSE signature over the payload. Returns
 * the hint of the key that verified.
 *
 * `digest` is the SHA-256 of the artifact the approval is for; the signed
 * in-toto statement must name it in a subject.
 */
export async function verifyKeyedBundle(root: TrustedRoot, bundle: Bundle, keys: readonly PinnedKey[], digest: Uint8Array): Promise<string> {
  if (bundle.certificate !== undefined) throw new Error("approval bundle must carry a key hint, not a certificate");
  const hint = bundle.publicKeyHint;
  if (hint === undefined || hint === "") throw new Error("approval bundle has no public key hint");
  if (bundle.dsse.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
    throw new Error(`unsupported DSSE payload type ${JSON.stringify(bundle.dsse.payloadType)}`);
  }
  // The hint identifies the key; a DSSE key id, even one equal to the hint,
  // never verifies.
  if (bundle.dsse.keyId !== "") throw new Error("DSSE key id must be empty for a key-signed bundle");
  const pinned = keys.find((k) => k.hint === hint);
  if (pinned === undefined) throw new Error("untrusted approval signing key");
  if (digest.length !== 32) throw new Error("expected artifact digest is not SHA-256");
  checkLayout(bundle, "none");

  const spki = await exportP256(pinned.key);
  const signed = preAuthEncoding(bundle.dsse.payloadType, bundle.dsse.payload);
  if (!(await verifyP256(pinned.key, bundle.dsse.signature, signed))) {
    throw new Error("DSSE signature does not verify under the pinned key");
  }

  await verifyLogEntries(root, bundle, { digest: toBase64(await sha256(signed)), signature: toBase64(bundle.dsse.signature), verifier: { publicKey: toBase64(spki) } });

  if (!statementNamesDigest(bundle.dsse.payload, toHex(digest))) {
    throw new Error("the statement's subjects do not name the artifact digest");
  }
  return hint;
}

/**
 * The entry rules above: a bounded count of hashedrekord 0.0.2 entries with
 * proofs only and no duplicates. `timestamps` says whether the bundle must
 * carry no RFC 3161 timestamp (a key-signed approval, whose time is inside
 * the statement) or exactly one bounded timestamp (a certificate-signed
 * approval, whose signing time that timestamp establishes).
 */
export function checkLayout(bundle: Bundle, timestamps: "none" | "one"): void {
  const entries = bundle.tlogEntries;
  if (entries.length === 0 || entries.length > MAX_LOG_RECEIPTS) {
    throw new Error(`approval requires between 1 and ${MAX_LOG_RECEIPTS} transparency log entries, got ${entries.length}`);
  }
  const seen = new Set<string>();
  entries.forEach((entry, i) => {
    if (entry.kind !== HASHEDREKORD_KIND || entry.version !== HASHEDREKORD_VERSION) {
      throw new Error(`transparency log entry ${i} is ${entry.kind} ${entry.version}, not ${HASHEDREKORD_KIND} ${HASHEDREKORD_VERSION}`);
    }
    if (entry.integratedTime !== undefined) throw new Error(`transparency log entry ${i} carries an integration time`);
    if (entry.inclusionPromise !== undefined) throw new Error(`transparency log entry ${i} carries an inclusion promise`);
    if (entry.inclusionProof === undefined) throw new Error(`transparency log entry ${i} has no inclusion proof`);
    const id = `${entry.logId}/${entry.inclusionProof.logIndex}`;
    if (seen.has(id)) throw new Error(`transparency log entry ${i} duplicates an earlier entry`);
    seen.add(id);
  });
  if (timestamps === "none" && bundle.rfc3161Timestamps.length !== 0) throw new Error("approval bundle must carry no RFC 3161 timestamps");
  if (timestamps === "one") signatureTimestamp(bundle);
}

/**
 * The one RFC 3161 timestamp a certificate-signed bundle carries over its
 * DSSE signature. Any other count, or an oversized timestamp, rejects.
 */
export function signatureTimestamp(bundle: Bundle): Uint8Array {
  const timestamps = bundle.rfc3161Timestamps;
  if (timestamps.length !== 1 || timestamps[0]!.length === 0 || timestamps[0]!.length > MAX_TIMESTAMP_SIZE) {
    throw new Error("certified registry endorsement requires one bounded signature timestamp");
  }
  return timestamps[0]!;
}

// ---------------------------------------------------------------- log entries

/** The base64 values the entry body must carry; the verifier is either the DER public key or the DER signing certificate. */
export interface ExpectedBody {
  readonly digest: string;
  readonly signature: string;
  readonly verifier: { readonly publicKey: string } | { readonly x509Certificate: string };
}

/** Verifies every log entry of `bundle` against the record it must carry. */
export async function verifyLogEntries(root: TrustedRoot, bundle: Bundle, expected: ExpectedBody): Promise<void> {
  for (let i = 0; i < bundle.tlogEntries.length; i++) {
    try {
      await verifyEntry(root, bundle.tlogEntries[i], expected);
    } catch (err) {
      throw new Error(`transparency log entry ${i}: ${message(err)}`);
    }
  }
}

const BODY_MEMBERS = ["apiVersion", "kind", "spec"];
const SPEC_MEMBERS = ["hashedRekordV002"];
const RECORD_MEMBERS = ["data", "signature"];
const DATA_MEMBERS = ["algorithm", "digest"];
const SIGNATURE_MEMBERS = ["content", "verifier"];
const VERIFIER_MEMBERS = ["publicKey", "x509Certificate", "keyDetails"];
const RAW_BYTES_MEMBERS = ["rawBytes"];
const HASH_ALGORITHM = "SHA2_256";
const KEY_DETAILS = "PKIX_ECDSA_P256_SHA_256";

async function verifyEntry(root: TrustedRoot, entry: TlogEntry, expected: ExpectedBody): Promise<void> {
  checkBody(entry.canonicalizedBody, expected);
  const proof = entry.inclusionProof;
  if (proof === undefined) throw new Error("no inclusion proof");
  const log = root.transparencyLogs.find((l) => l.logId === entry.logId);
  if (log === undefined) throw new Error("names a transparency log the trusted root does not list");
  const origin = await logOrigin(root, log);
  const checkpoint = await verifyCheckpoint(proof.checkpoint, log, origin);
  if (checkpoint.size !== proof.treeSize || !bytesEqual(checkpoint.rootHash, proof.rootHash)) {
    throw new Error("inclusion proof does not state the checkpoint's tree size and root hash");
  }
  const leafHash = await sha256(concat(new Uint8Array([0x00]), entry.canonicalizedBody));
  await verifyMerkleInclusion(leafHash, proof.logIndex, checkpoint.size, proof.hashes, checkpoint.rootHash);
}

/**
 * The body must be the canonical hashedrekord 0.0.2 record for this
 * envelope and signer: SHA2_256 of the signed message, the DSSE signature,
 * and the DER public key or signing certificate with its key details.
 */
function checkBody(body: Uint8Array, expected: ExpectedBody): void {
  let value: JsonValue;
  try {
    value = strictParse(body);
  } catch (err) {
    throw new Error(`parsing body: ${message(err)}`);
  }
  if (value === null) throw new Error("body is null");
  const record = object(value, "body", BODY_MEMBERS);
  const kind = str(record, "kind");
  const version = str(record, "apiVersion");
  if (kind !== HASHEDREKORD_KIND || version !== HASHEDREKORD_VERSION) {
    throw new Error(`body is ${kind} ${version}, not ${HASHEDREKORD_KIND} ${HASHEDREKORD_VERSION}`);
  }
  const spec = struct(struct(record, "spec", SPEC_MEMBERS), "hashedRekordV002", RECORD_MEMBERS);
  const data = struct(spec, "data", DATA_MEMBERS);
  if (str(data, "algorithm") !== HASH_ALGORITHM) throw new Error("body digest algorithm is not SHA2_256");
  if (str(data, "digest") !== expected.digest) throw new Error("body digest is not the digest of the signed message");
  const signature = struct(spec, "signature", SIGNATURE_MEMBERS);
  if (str(signature, "content") !== expected.signature) throw new Error("body signature is not the DSSE signature");
  const verifier = struct(signature, "verifier", VERIFIER_MEMBERS);
  if (str(verifier, "keyDetails") !== KEY_DETAILS) throw new Error("body key details are not ECDSA P-256 with SHA-256");
  if ("publicKey" in expected.verifier) {
    if (verifier.has("x509Certificate")) throw new Error("body names a certificate, not the pinned key");
    if (str(struct(verifier, "publicKey", RAW_BYTES_MEMBERS), "rawBytes") !== expected.verifier.publicKey) {
      throw new Error("body public key is not the pinned key");
    }
  } else {
    if (verifier.has("publicKey")) throw new Error("body names a public key, not the signing certificate");
    if (str(struct(verifier, "x509Certificate", RAW_BYTES_MEMBERS), "rawBytes") !== expected.verifier.x509Certificate) {
      throw new Error("body certificate is not the signing certificate");
    }
  }
  if (!bytesEqual(canonicalize(value), body)) throw new Error("body is not in canonical form");
}

// ---------------------------------------------------------------- checkpoints

/** The tree state a checkpoint states, once its signature has verified. */
export interface Checkpoint {
  readonly origin: string;
  readonly size: bigint;
  readonly rootHash: Uint8Array;
}

/** The sentinel that opens a signature line of a signed note. */
const SIGNATURE_PREFIX = "— ";
const MAX_NOTE_SIGNATURES = 100;
const MAX_UINT64 = (1n << 64n) - 1n;

/**
 * Verifies a checkpoint envelope (a signed note) under `log`, whose
 * signature line is named `origin` and keyed by the log key's note hint, and
 * returns the tree state it states; the checkpoint's origin must be `origin`.
 * Signature lines of other signers are ignored.
 */
export async function verifyCheckpoint(envelope: string, log: KeyedAuthority, origin: string): Promise<Checkpoint> {
  for (const ch of envelope) {
    const c = ch.codePointAt(0) as number;
    if (c < 0x20 && c !== 0x0a) throw new Error("checkpoint contains a control character");
  }
  const split = envelope.lastIndexOf("\n\n");
  if (split < 0) throw new Error("checkpoint has no signature section");
  const text = envelope.slice(0, split + 1);
  const section = envelope.slice(split + 2);
  if (section.length === 0 || !section.endsWith("\n")) throw new Error("checkpoint signature section is malformed");
  const lines = section.slice(0, -1).split("\n");
  if (lines.length > MAX_NOTE_SIGNATURES) throw new Error("checkpoint has too many signatures");

  const hint = await noteKeyHint(log, origin);
  let verified = false;
  for (const line of lines) {
    if (!line.startsWith(SIGNATURE_PREFIX)) throw new Error("checkpoint signature line is malformed");
    const rest = line.slice(SIGNATURE_PREFIX.length);
    const space = rest.indexOf(" ");
    const name = space < 0 ? rest : rest.slice(0, space);
    const encoded = space < 0 ? "" : rest.slice(space + 1);
    if (!validNoteName(name) || encoded === "") throw new Error("checkpoint signature line is malformed");
    let signature: Uint8Array;
    try {
      signature = decodeBase64("checkpoint signature", encoded);
    } catch {
      throw new Error("checkpoint signature line is malformed");
    }
    if (signature.length < 5) throw new Error("checkpoint signature line is malformed");
    if (name !== origin || !bytesEqual(signature.subarray(0, 4), hint) || verified) continue;
    if (!(await verifyLogSignature(log.publicKey, utf8(text), signature.subarray(4)))) {
      throw new Error("checkpoint signature does not verify under the log key");
    }
    verified = true;
  }
  if (!verified) throw new Error("checkpoint is not signed by the log");

  const parts = text.split("\n");
  if (parts.length < 4) throw new Error("checkpoint has too few lines");
  const [stated, sizeText, hashText] = parts;
  if (stated === "") throw new Error("checkpoint has an empty origin");
  if (stated !== origin) throw new Error(`checkpoint origin ${JSON.stringify(stated)} is not the log's ${JSON.stringify(origin)}`);
  if (!/^[0-9]+$/.test(sizeText) || BigInt(sizeText) > MAX_UINT64) throw new Error("checkpoint tree size is not a 64-bit integer");
  let rootHash: Uint8Array;
  try {
    rootHash = decodeBase64("checkpoint root hash", hashText);
  } catch (err) {
    throw new Error(`checkpoint root hash: ${message(err)}`);
  }
  if (rootHash.length !== 32) throw new Error("checkpoint root hash is not 32 bytes");
  return { origin: stated, size: BigInt(sizeText), rootHash };
}

/** A note signer name: non-empty, no whitespace, no '+'. */
function validNoteName(name: string): boolean {
  return name !== "" && !/[\s+]/.test(name);
}

/**
 * The 4-byte key hint a log's signature line carries: for an ECDSA key the
 * leading bytes of SHA-256 over its DER form; for an Ed25519 key the leading
 * bytes of SHA-256 over the origin, a newline, the byte 0x01 and the raw key.
 */
async function noteKeyHint(log: KeyedAuthority, origin: string): Promise<Uint8Array> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", log.publicKey));
  switch (log.publicKey.algorithm.name) {
    case "ECDSA":
      return (await sha256(spki)).subarray(0, 4);
    case "Ed25519":
      return (await sha256(concat(utf8(origin), new Uint8Array([0x0a, 0x01]), rawKey(spki)))).subarray(0, 4);
    default:
      throw new Error(`unsupported transparency log key type ${log.publicKey.algorithm.name}`);
  }
}

/** The subjectPublicKey bits of a SubjectPublicKeyInfo. */
function rawKey(spki: Uint8Array): Uint8Array {
  const parts = expectSequence(decode(spki), "SubjectPublicKeyInfo");
  if (parts.length !== 2) throw new Error("SubjectPublicKeyInfo must hold an algorithm and a key");
  return bitString(parts[1]);
}

/** Verifies a signature under a transparency log's key: DER ECDSA over the curve's hash, or a raw Ed25519 signature. */
export async function verifyLogSignature(key: CryptoKey, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    if (key.algorithm.name === "Ed25519") {
      return await crypto.subtle.verify({ name: "Ed25519" }, key, asBuffer(signature), asBuffer(data));
    }
    const curve = (key.algorithm as EcKeyAlgorithm).namedCurve;
    const size = curve === "P-256" ? 32 : curve === "P-384" ? 48 : curve === "P-521" ? 66 : undefined;
    if (size === undefined) return false;
    const hash = curve === "P-256" ? "SHA-256" : curve === "P-384" ? "SHA-384" : "SHA-512";
    const raw = ecdsaSignatureToRaw(signature, size);
    return await crypto.subtle.verify({ name: "ECDSA", hash }, key, asBuffer(raw), asBuffer(data));
  } catch {
    return false;
  }
}

/**
 * The first log entry's integration time, proven by the log's inclusion
 * promise: a signature under the key of the log the entry names, listed in
 * `root` and valid at that time, over the canonical record of the entry's
 * body, integration time, index and log id. Undefined when the first entry
 * states no time or carries no promise; a log the root does not list, a time
 * outside the key's validity, or a promise that does not verify rejects.
 */
export async function promisedLogTime(root: TrustedRoot, entries: readonly TlogEntry[]): Promise<Date | undefined> {
  const first = entries[0];
  if (first === undefined || first.integratedTime === undefined || first.inclusionPromise === undefined) return undefined;
  const log = root.transparencyLogs.find((l) => l.logId === first.logId);
  if (log === undefined) throw new Error("first log entry names a transparency log the trusted root does not list");
  const at = new Date(Number(first.integratedTime) * 1000);
  // A time outside the representable range reads as an invalid date, which no window comparison rejects.
  if (!Number.isFinite(at.getTime())) throw new Error("first log entry's integration time is not a representable time");
  if (at.getTime() < log.validFrom.getTime() || (log.validTo !== undefined && at.getTime() > log.validTo.getTime())) {
    throw new Error("first log entry's integration time is outside the log key's validity");
  }
  const record = new Map<string, JsonValue>([
    ["body", toBase64(first.canonicalizedBody)],
    ["integratedTime", new JsonNumber(first.integratedTime.toString())],
    ["logID", first.logId],
    ["logIndex", new JsonNumber(first.logIndex.toString())],
  ]);
  if (!(await verifyLogSignature(log.publicKey, canonicalize(record), first.inclusionPromise))) {
    throw new Error("first log entry's inclusion promise does not verify under the log key");
  }
  return at;
}

/** The host name of the log's base URL in the trusted root: the origin its checkpoints must state. */
async function logOrigin(root: TrustedRoot, log: KeyedAuthority): Promise<string> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", log.publicKey));
  const tlogs = arr(object(root.json, "trusted root"), "tlogs") ?? [];
  for (const entry of tlogs) {
    if (entry === null) continue;
    const record = object(entry, "tlog");
    const rawBytes = str(struct(record, "publicKey", ["rawBytes", "keyDetails", "validFor"]), "rawBytes");
    if (rawBytes === "" || !bytesEqual(decodeBase64("publicKey rawBytes", rawBytes), spki)) continue;
    const baseUrl = str(record, "baseUrl");
    let hostname: string;
    try {
      hostname = new URL(baseUrl).hostname;
    } catch {
      throw new Error(`transparency log base URL ${JSON.stringify(baseUrl)} is not a URL`);
    }
    if (hostname === "") throw new Error(`transparency log base URL ${JSON.stringify(baseUrl)} has no host`);
    return hostname;
  }
  throw new Error("transparency log has no base URL in the trusted root");
}

// ---------------------------------------------------------------- Merkle inclusion

/**
 * Verifies an RFC 6962 inclusion proof: `hashes` carries the sibling hashes
 * from the leaf at `index` up to the root of a tree of `size` leaves, inner
 * nodes first and then the nodes along the tree's right border.
 */
export async function verifyMerkleInclusion(
  leafHash: Uint8Array,
  index: bigint,
  size: bigint,
  hashes: readonly Uint8Array[],
  rootHash: Uint8Array,
): Promise<void> {
  if (index < 0n || index >= size) throw new Error(`inclusion proof index ${index} is outside a tree of ${size} leaves`);
  if (leafHash.length !== 32) throw new Error("inclusion proof leaf hash is not 32 bytes");
  const inner = bitLength(index ^ (size - 1n));
  const border = onesCount(index >> BigInt(inner));
  if (hashes.length !== inner + border) {
    throw new Error(`inclusion proof has ${hashes.length} hashes, expected ${inner + border}`);
  }
  for (const h of hashes) if (h.length !== 32) throw new Error("inclusion proof hash is not 32 bytes");
  let node = leafHash;
  for (let i = 0; i < inner; i++) {
    const sibling = hashes[i];
    node = (index >> BigInt(i)) & 1n ? await hashChildren(sibling, node) : await hashChildren(node, sibling);
  }
  for (let i = inner; i < hashes.length; i++) node = await hashChildren(hashes[i], node);
  if (!bytesEqual(node, rootHash)) throw new Error("inclusion proof does not reach the root hash");
}

function hashChildren(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

function bitLength(n: bigint): number {
  return n === 0n ? 0 : n.toString(2).length;
}

function onesCount(n: bigint): number {
  return n.toString(2).split("1").length - 1;
}

// ---------------------------------------------------------------- statements

/**
 * Whether a subject of the in-toto statement carries `digestHex` as its
 * sha256 digest. Every digest value must be hex.
 */
export function statementNamesDigest(payload: Uint8Array, digestHex: string): boolean {
  let value: JsonValue;
  try {
    value = strictParse(payload);
  } catch (err) {
    throw new Error(`parsing in-toto statement: ${message(err)}`);
  }
  if (!(value instanceof Map)) throw new Error("in-toto statement is not an object");
  const subjects = arr(value, "subject") ?? [];
  let found = false;
  subjects.forEach((s, i) => {
    if (s === null) throw new Error(`in-toto statement subject ${i} is null`);
    const subject = object(s, `subject[${i}]`);
    const digests = subject.get("digest");
    if (digests === undefined || digests === null) return;
    for (const [algorithm, v] of object(digests, `subject[${i}] digest`)) {
      if (typeof v !== "string" || !/^[0-9a-fA-F]*$/.test(v) || v.length % 2 !== 0) {
        throw new Error(`in-toto statement subject ${i} digest ${JSON.stringify(algorithm)} is not hex`);
      }
      if (algorithm === "sha256" && v.toLowerCase() === digestHex) found = true;
    }
  });
  return found;
}

// ---------------------------------------------------------------- keys

/** Imports a DER SubjectPublicKeyInfo as an extractable ECDSA P-256 verification key. */
export async function importP256(spki: Uint8Array): Promise<CryptoKey> {
  if (!isP256(spki)) throw new Error("approval requires an ECDSA P-256 key");
  try {
    return await crypto.subtle.importKey("spki", asBuffer(spki), P256, true, ["verify"]);
  } catch (err) {
    throw new Error(`importing signing key: ${message(err)}`);
  }
}

/** Whether the SubjectPublicKeyInfo names the ecPublicKey algorithm on the P-256 curve. */
function isP256(spki: Uint8Array): boolean {
  try {
    const parts = expectSequence(decode(spki), "SubjectPublicKeyInfo");
    if (parts.length !== 2 || !isUniversal(parts[1], TAG.BIT_STRING)) return false;
    const alg = expectSequence(parts[0], "key AlgorithmIdentifier");
    return alg.length === 2 && oid(alg[0]) === OID_EC_PUBLIC_KEY && oid(alg[1]) === OID_P256;
  } catch {
    return false;
  }
}

/** The DER form of a P-256 verification key; any other key rejects. */
async function exportP256(key: CryptoKey): Promise<Uint8Array> {
  const algorithm = key.algorithm as EcKeyAlgorithm;
  if (key.type !== "public" || algorithm.name !== "ECDSA" || algorithm.namedCurve !== "P-256") {
    throw new Error("approval requires an ECDSA P-256 key");
  }
  try {
    return new Uint8Array(await crypto.subtle.exportKey("spki", key));
  } catch (err) {
    throw new Error(`exporting signing key: ${message(err)}`);
  }
}

/** Verifies a DER ECDSA signature over SHA-256 of `data`; false for a malformed or bad signature. */
export async function verifyP256(key: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  let raw: Uint8Array;
  try {
    raw = ecdsaSignatureToRaw(signature, 32);
  } catch (err) {
    if (err instanceof DerError) return false;
    throw err;
  }
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, asBuffer(raw), asBuffer(data));
}

// ---------------------------------------------------------------- helpers

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Standard base64 with padding. */
export function toBase64(b: Uint8Array): string {
  let s = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    s += BASE64[n >> 18] + BASE64[(n >> 12) & 63] + BASE64[(n >> 6) & 63] + BASE64[n & 63];
  }
  if (i < b.length) {
    const second = i + 1 < b.length;
    const n = (b[i] << 16) | ((second ? b[i + 1] : 0) << 8);
    s += BASE64[n >> 18] + BASE64[(n >> 12) & 63] + (second ? BASE64[(n >> 6) & 63] : "=") + "=";
  }
  return s;
}

function asBuffer(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return b as Uint8Array<ArrayBuffer>;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
