/**
 * Sigstore bundle wire checks shared by every bundle kind: version 0.3 media
 * type, verification material, exactly one DSSE signature, and the shape of
 * transparency-log entries.
 */
import { toHex } from "../bytes.js";
import { decodeBase64 } from "../canonical.js";
import { arr, object, optStruct, str, strArr, struct } from "../json/decode.js";
import { JsonNumber, serialize, type JsonObject, type JsonValue } from "../json/index.js";

export const BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
export const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const MAX_BUNDLE_SIZE = 4 << 20;

export interface TlogEntry {
  readonly logId: string;
  readonly kind: string;
  readonly version: string;
  /** Seconds since the epoch; absent for entries anchored by a timestamp instead. */
  readonly integratedTime?: bigint;
  readonly canonicalizedBody: Uint8Array;
  readonly inclusionPromise?: Uint8Array;
  readonly inclusionProof?: InclusionProof;
}

export interface InclusionProof {
  readonly logIndex: bigint;
  readonly rootHash: Uint8Array;
  readonly treeSize: bigint;
  readonly hashes: readonly Uint8Array[];
  readonly checkpoint: string;
}

/** A bundle decoded far enough to route it: the parts every verifier reads. */
export interface Bundle {
  readonly json: JsonValue;
  readonly mediaType: string;
  /** DER leaf certificate, for certificate-signed bundles. */
  readonly certificate?: Uint8Array;
  /** The key hint, for key-signed bundles. */
  readonly publicKeyHint?: string;
  readonly tlogEntries: readonly TlogEntry[];
  readonly rfc3161Timestamps: readonly Uint8Array[];
  readonly dsse: { readonly payloadType: string; readonly payload: Uint8Array; readonly signature: Uint8Array; readonly keyId: string };
}

// Member sets of the bundle records; a member outside them rejects.
const BUNDLE_MEMBERS = ["mediaType", "verificationMaterial", "dsseEnvelope", "messageSignature"];
const MATERIAL_MEMBERS = ["publicKey", "x509CertificateChain", "certificate", "tlogEntries", "timestampVerificationData"];
const CERTIFICATE_MEMBERS = ["rawBytes"];
const PUBLIC_KEY_MEMBERS = ["hint"];
const ENTRY_MEMBERS = ["logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise", "inclusionProof", "canonicalizedBody"];
const LOG_ID_MEMBERS = ["keyId"];
const KIND_VERSION_MEMBERS = ["kind", "version"];
const PROMISE_MEMBERS = ["signedEntryTimestamp"];
const PROOF_MEMBERS = ["logIndex", "rootHash", "treeSize", "hashes", "checkpoint"];
const CHECKPOINT_MEMBERS = ["envelope"];
const TIMESTAMP_DATA_MEMBERS = ["rfc3161Timestamps"];
const TIMESTAMP_MEMBERS = ["signedTimestamp"];
const ENVELOPE_MEMBERS = ["payload", "payloadType", "signatures"];
const SIGNATURE_MEMBERS = ["sig", "keyid"];

/**
 * Decodes a bundle and enforces the shared rules: version 0.3 media type; a
 * certificate or a key hint but not the legacy certificate-chain layout; a
 * DSSE envelope with exactly one signature.
 */
export function parseBundle(json: JsonValue): Bundle {
  if (bundleBytes(json).length > MAX_BUNDLE_SIZE) {
    throw new Error(`bundle exceeds ${MAX_BUNDLE_SIZE} bytes`);
  }
  if (json === null) throw new Error("bundle is null");
  const bundle = object(json, "bundle", BUNDLE_MEMBERS);
  const mediaType = str(bundle, "mediaType");
  if (mediaType !== BUNDLE_MEDIA_TYPE) {
    throw new Error(`unsupported bundle media type ${JSON.stringify(mediaType)}`);
  }

  const material = struct(bundle, "verificationMaterial", MATERIAL_MEMBERS);
  if (isSet(material, "x509CertificateChain")) {
    throw new Error("legacy bundle format not supported: the x509CertificateChain layout requires the v0.3 single-certificate form");
  }
  const certificateRecord = optStruct(material, "certificate", CERTIFICATE_MEMBERS);
  const publicKeyRecord = optStruct(material, "publicKey", PUBLIC_KEY_MEMBERS);
  if ((certificateRecord === undefined) === (publicKeyRecord === undefined)) {
    throw new Error("bundle verification material must carry exactly one of a certificate or a public key hint");
  }
  let certificate: Uint8Array | undefined;
  if (certificateRecord !== undefined) {
    certificate = decodeBase64("certificate rawBytes", str(certificateRecord, "rawBytes"));
    if (certificate.length === 0) throw new Error("bundle certificate is empty");
  }
  const publicKeyHint = publicKeyRecord === undefined ? undefined : str(publicKeyRecord, "hint");

  const tlogEntries = (arr(material, "tlogEntries") ?? []).map((entry, i) => {
    if (entry === null) throw new Error(`bundle tlogEntries[${i}] is null`);
    return tlogEntry(object(entry, `tlogEntries[${i}]`, ENTRY_MEMBERS));
  });
  const timestampData = struct(material, "timestampVerificationData", TIMESTAMP_DATA_MEMBERS);
  const rfc3161Timestamps = (arr(timestampData, "rfc3161Timestamps") ?? []).map((ts, i) => {
    if (ts === null) throw new Error(`bundle rfc3161Timestamps[${i}] is null`);
    const signed = decodeBase64("signedTimestamp", str(object(ts, `rfc3161Timestamps[${i}]`, TIMESTAMP_MEMBERS), "signedTimestamp"));
    if (signed.length === 0) throw new Error("bundle RFC 3161 timestamp is empty");
    return signed;
  });

  if (isSet(bundle, "messageSignature")) throw new Error("bundle carries a message signature instead of a DSSE envelope");
  if (!isSet(bundle, "dsseEnvelope")) throw new Error("bundle has no DSSE envelope");
  const envelope = struct(bundle, "dsseEnvelope", ENVELOPE_MEMBERS);
  const signatures = arr(envelope, "signatures") ?? [];
  if (signatures.length !== 1) {
    throw new Error(`DSSE envelope must have exactly one signature, got ${signatures.length}`);
  }
  const signatureRecord = signatures[0]!;
  if (signatureRecord === null) throw new Error("DSSE signature is null");
  const sig = object(signatureRecord, "signature", SIGNATURE_MEMBERS);
  const signature = decodeBase64("sig", str(sig, "sig"));
  if (signature.length === 0) throw new Error("DSSE signature is empty");
  const payloadType = str(envelope, "payloadType");
  if (payloadType === "") throw new Error("DSSE envelope has no payload type");
  const payload = decodeBase64("payload", str(envelope, "payload"));
  if (payload.length === 0) throw new Error("DSSE envelope has no payload");

  return {
    json,
    mediaType,
    ...(certificate === undefined ? {} : { certificate }),
    ...(publicKeyHint === undefined ? {} : { publicKeyHint }),
    tlogEntries,
    rfc3161Timestamps,
    dsse: { payloadType, payload, signature, keyId: str(sig, "keyid") },
  };
}

/** Serializes a parsed bundle value for the Sigstore library. */
export function bundleBytes(json: JsonValue): Uint8Array {
  return serialize(json);
}

/** Whether a member is present and not null: how an optional record counts as set. */
function isSet(o: JsonObject, key: string): boolean {
  const v = o.get(key);
  return v !== undefined && v !== null;
}

function tlogEntry(o: JsonObject): TlogEntry {
  const logIdRecord = struct(o, "logId", LOG_ID_MEMBERS);
  const logIdBytes = decodeBase64("logId keyId", str(logIdRecord, "keyId"));
  if (logIdBytes.length !== 32) throw new Error("transparency log entry log id is not 32 bytes");
  const kindVersion = struct(o, "kindVersion", KIND_VERSION_MEMBERS);
  const kind = str(kindVersion, "kind");
  const version = str(kindVersion, "version");
  if (kind === "" || version === "") throw new Error("transparency log entry has no kind and version");
  const canonicalizedBody = decodeBase64("canonicalizedBody", str(o, "canonicalizedBody"));
  if (canonicalizedBody.length === 0) throw new Error("transparency log entry has no body");
  // The entry's own logIndex is decoded for its range only; the inclusion proof's index is what verification uses.
  unsigned64(o, "logIndex");
  const integratedTime = unsigned64(o, "integratedTime");

  const promise = optStruct(o, "inclusionPromise", PROMISE_MEMBERS);
  let inclusionPromise: Uint8Array | undefined;
  if (promise !== undefined) {
    inclusionPromise = decodeBase64("signedEntryTimestamp", str(promise, "signedEntryTimestamp"));
    if (inclusionPromise.length === 0) throw new Error("transparency log inclusion promise is empty");
  }

  const proof = optStruct(o, "inclusionProof", PROOF_MEMBERS);
  let inclusionProof: InclusionProof | undefined;
  if (proof !== undefined) {
    const rootHash = decodeBase64("rootHash", str(proof, "rootHash"));
    if (rootHash.length === 0) throw new Error("transparency log inclusion proof has no root hash");
    const checkpoint = str(struct(proof, "checkpoint", CHECKPOINT_MEMBERS), "envelope");
    if (checkpoint === "") throw new Error("transparency log inclusion proof has no checkpoint");
    inclusionProof = {
      logIndex: unsigned64(proof, "logIndex") ?? 0n,
      rootHash,
      treeSize: unsigned64(proof, "treeSize") ?? 0n,
      hashes: (strArr(proof, "hashes") ?? []).map((h) => decodeBase64("hashes", h)),
      checkpoint,
    };
  }

  return {
    logId: toHex(logIdBytes),
    kind,
    version,
    ...(integratedTime === undefined || integratedTime === 0n ? {} : { integratedTime }),
    canonicalizedBody,
    ...(inclusionPromise === undefined ? {} : { inclusionPromise }),
    ...(inclusionProof === undefined ? {} : { inclusionProof }),
  };
}

const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

/**
 * A non-negative 64-bit integer member written as a JSON number or, as
 * protobuf JSON does, a decimal string; absent or null is undefined.
 */
function unsigned64(o: JsonObject, key: string): bigint | undefined {
  const v = o.get(key);
  if (v === undefined || v === null) return undefined;
  let n: bigint;
  if (typeof v === "string") {
    if (!DECIMAL.test(v)) throw new Error(`bundle member ${JSON.stringify(key)} is not a non-negative integer`);
    n = BigInt(v);
  } else if (v instanceof JsonNumber) {
    if (v.raw.startsWith("-")) throw new Error(`bundle member ${JSON.stringify(key)} is negative`);
    n = v.toBigInt();
  } else {
    throw new Error(`bundle member ${JSON.stringify(key)} is not an integer`);
  }
  if (n >= 1n << 63n) throw new Error(`bundle member ${JSON.stringify(key)} overflows int64`);
  return n;
}
