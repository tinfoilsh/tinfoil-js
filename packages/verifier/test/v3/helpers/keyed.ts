/**
 * Minting of key-signed bundles for tests: a fresh P-256 signing key, a
 * transparency log (ECDSA or Ed25519) that signs checkpoints over small
 * RFC 6962 Merkle trees, and a trusted root that lists the log and any
 * timestamp authorities.
 */
import { concat, sha256, toHex, utf8 } from "../../../src/v3/internal/bytes.js";
import { strictParse, type JsonValue } from "../../../src/v3/internal/json/index.js";
import { BUNDLE_MEDIA_TYPE, IN_TOTO_PAYLOAD_TYPE, parseBundle } from "../../../src/v3/internal/sigstore/bundle.js";
import { keyHint, verifyKeyedBundle, type PinnedKey } from "../../../src/v3/internal/sigstore/keyed.js";
import { preAuthEncoding } from "../../../src/v3/internal/sigstore/timestamp.js";
import { parseTrustedRoot, TRUSTED_ROOT_MEDIA_TYPE, type TrustedRoot } from "../../../src/v3/internal/sigstore/trusted-root.js";

export const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
export const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));
export const toJson = (value: unknown): JsonValue => strictParse(utf8(JSON.stringify(value)));
export const bytes = (...b: number[]): Uint8Array => new Uint8Array(b);

export const P256: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };

/** A copy of a plain JSON value with `mutate` applied. */
export function mutated<T>(value: T, mutate: (v: any) => void): T {
  const copy = structuredClone(value) as T;
  mutate(copy);
  return copy;
}

/** A DER ECDSA signature from WebCrypto's fixed-width r‖s form. */
export function derSignature(raw: Uint8Array): Uint8Array {
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

export function pem(spki: Uint8Array): string {
  const lines = b64(spki).match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

export interface Signer {
  readonly pair: CryptoKeyPair;
  readonly spki: Uint8Array;
  readonly hint: string;
  readonly pem: string;
}

export async function newSigner(): Promise<Signer> {
  const pair = await crypto.subtle.generateKey(P256, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  return { pair, spki, hint: await keyHint(spki), pem: pem(spki) };
}

export async function signP256(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return derSignature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data as Uint8Array<ArrayBuffer>)));
}

/** A transparency log: its key, origin, and the id its entries carry. */
export interface TestLog {
  readonly kind: "ecdsa" | "ed25519";
  readonly origin: string;
  readonly pair: CryptoKeyPair;
  readonly spki: Uint8Array;
  readonly logId: Uint8Array;
}

export async function newLog(kind: TestLog["kind"], origin = "log.test.invalid"): Promise<TestLog> {
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
export async function signNote(log: TestLog, text: string, name = log.origin): Promise<string> {
  const data = utf8(text);
  const sig =
    log.kind === "ecdsa"
      ? await signP256(log.pair.privateKey, data)
      : new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, log.pair.privateKey, data as Uint8Array<ArrayBuffer>));
  return `— ${name} ${b64(concat(log.logId.subarray(0, 4), sig))}\n`;
}

export interface AuthorityJson {
  readonly certificates: readonly string[];
  readonly start: string;
  readonly end?: string;
}

export function rootJson(logs: readonly TestLog[], authorities: readonly AuthorityJson[] = []): unknown {
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

export function rootOf(logs: readonly TestLog[], authorities: readonly AuthorityJson[] = []): Promise<TrustedRoot> {
  return parseTrustedRoot(utf8(JSON.stringify(rootJson(logs, authorities))));
}

// RFC 6962 trees over the leaves of a test log.
export const leafHash = (leaf: Uint8Array): Promise<Uint8Array> => sha256(concat(bytes(0x00), leaf));
export const nodeHash = (l: Uint8Array, r: Uint8Array): Promise<Uint8Array> => sha256(concat(bytes(0x01), l, r));

/** The largest power of two less than n. */
export function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export async function treeRoot(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 1) return leafHash(leaves[0]);
  const k = splitPoint(leaves.length);
  return nodeHash(await treeRoot(leaves.slice(0, k)), await treeRoot(leaves.slice(k)));
}

export async function inclusionPath(leaves: readonly Uint8Array[], index: number): Promise<Uint8Array[]> {
  if (leaves.length === 1) return [];
  const k = splitPoint(leaves.length);
  return index < k
    ? [...(await inclusionPath(leaves.slice(0, k), index)), await treeRoot(leaves.slice(k))]
    : [...(await inclusionPath(leaves.slice(k), index - k)), await treeRoot(leaves.slice(0, k))];
}

export const ARTIFACT = utf8("the approved artifact bytes");

export interface BuildOptions {
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

export interface Built {
  readonly json: unknown;
  readonly payload: Uint8Array;
  readonly digest: Uint8Array;
}

/** A key-signed bundle over a statement naming the artifact, with entries in `log`. */
export async function build(signer: Signer, log: TestLog, opts: BuildOptions = {}): Promise<Built> {
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
  if (!Number.isInteger(count) || count < 1) throw new Error("a bundle needs at least one log entry; omit the entry instead to test an empty log");
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

export function verify(root: TrustedRoot, json: unknown, keys: readonly PinnedKey[], digest: Uint8Array): Promise<string> {
  return verifyKeyedBundle(root, parseBundle(toJson(json)), keys, digest);
}
