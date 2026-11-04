/**
 * The Sigstore trusted root: certificate authorities, transparency logs,
 * certificate-transparency logs and timestamp authorities, each with a
 * validity window.
 */
import { SIGSTORE_TRUSTED_ROOT_JSON } from "../../trust/sigstore-trusted-root.js";
import { sha256, toHex, utf8 } from "../bytes.js";
import { decodeBase64 } from "../canonical.js";
import { arr, object, optStruct, str, struct } from "../json/decode.js";
import { strictParse, type JsonObject, type JsonValue } from "../json/index.js";

export const TRUSTED_ROOT_MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1";

export interface KeyedAuthority {
  /** Lowercase hex SHA-256 of the DER public key, the id log entries name. */
  readonly logId: string;
  readonly publicKey: CryptoKey;
  readonly validFrom: Date;
  readonly validTo?: Date;
}

export interface CertificateAuthority {
  /** Root first. */
  readonly chainDer: readonly Uint8Array[];
  readonly validFrom: Date;
  readonly validTo?: Date;
}

export interface TrustedRoot {
  /** As parsed, for handing to the Sigstore library. */
  readonly json: JsonValue;
  readonly certificateAuthorities: readonly CertificateAuthority[];
  readonly transparencyLogs: readonly KeyedAuthority[];
  readonly ctLogs: readonly KeyedAuthority[];
  readonly timestampAuthorities: readonly CertificateAuthority[];
}

// Member sets of the trusted-root records; a member outside them rejects.
const ROOT_MEMBERS = ["mediaType", "tlogs", "certificateAuthorities", "ctlogs", "timestampAuthorities"];
const LOG_MEMBERS = ["baseUrl", "hashAlgorithm", "publicKey", "logId", "checkpointKeyId", "operator"];
const PUBLIC_KEY_MEMBERS = ["rawBytes", "keyDetails", "validFor"];
const AUTHORITY_MEMBERS = ["subject", "uri", "certChain", "validFor", "operator"];
const CHAIN_MEMBERS = ["certificates"];
const CERTIFICATE_MEMBERS = ["rawBytes"];
const VALIDITY_MEMBERS = ["start", "end"];
const LOG_ID_MEMBERS = ["keyId"];

/** The WebCrypto import parameters for each key type a log may declare. */
const KEY_ALGORITHMS: Readonly<Record<string, EcKeyImportParams | Algorithm>> = {
  PKIX_ECDSA_P256_SHA_256: { name: "ECDSA", namedCurve: "P-256" },
  PKIX_ECDSA_P384_SHA_384: { name: "ECDSA", namedCurve: "P-384" },
  PKIX_ECDSA_P521_SHA_512: { name: "ECDSA", namedCurve: "P-521" },
  PKIX_ED25519: { name: "Ed25519" },
};

/** Parses trusted-root JSON (media type trustedroot+json version 0.1). */
export async function parseTrustedRoot(json: Uint8Array): Promise<TrustedRoot> {
  let value: JsonValue;
  try {
    value = strictParse(json);
  } catch (err) {
    throw new Error(`parsing trusted root: ${(err as Error).message}`);
  }
  if (value === null) throw new Error("parsing trusted root: document is null");
  const root = object(value, "trusted root", ROOT_MEMBERS);
  const mediaType = str(root, "mediaType");
  if (mediaType !== TRUSTED_ROOT_MEDIA_TYPE) {
    throw new Error(`unsupported trusted root media type ${JSON.stringify(mediaType)}`);
  }
  return {
    json: value,
    certificateAuthorities: list(root, "certificateAuthorities", AUTHORITY_MEMBERS).map(authority),
    transparencyLogs: await Promise.all(list(root, "tlogs", LOG_MEMBERS).map(keyedAuthority)),
    ctLogs: await Promise.all(list(root, "ctlogs", LOG_MEMBERS).map(keyedAuthority)),
    timestampAuthorities: list(root, "timestampAuthorities", AUTHORITY_MEMBERS).map(authority),
  };
}

let embedded: Promise<TrustedRoot> | undefined;

/** The embedded production trusted root. Parsed once; the result is shared. */
export function embeddedTrustedRoot(): Promise<TrustedRoot> {
  if (embedded === undefined) {
    embedded = parseTrustedRoot(utf8(SIGSTORE_TRUSTED_ROOT_JSON)).catch((err: unknown) => {
      embedded = undefined;
      throw err;
    });
  }
  return embedded;
}

/** An array member of records with exactly `members`; absent is empty. A null element rejects. */
function list(o: JsonObject, key: string, members: readonly string[]): JsonObject[] {
  const items = arr(o, key) ?? [];
  return items.map((item, i) => {
    if (item === null) throw new Error(`trusted root ${key}[${i}] is null`);
    return object(item, `${key}[${i}]`, members);
  });
}

/** A certificate authority: its chain, reordered root first, and its validity window. */
function authority(o: JsonObject): CertificateAuthority {
  const chain = struct(o, "certChain", CHAIN_MEMBERS);
  const certificates = arr(chain, "certificates") ?? [];
  if (certificates.length === 0) throw new Error("trusted root certificate authority has an empty certificate chain");
  // The wire order is leaf (issuing certificate) first, root last.
  const chainDer = certificates
    .map((c, i) => {
      if (c === null) throw new Error(`trusted root certificate chain entry ${i} is null`);
      const der = decodeBase64("certificate rawBytes", str(object(c, "certificate", CERTIFICATE_MEMBERS), "rawBytes"));
      if (der.length === 0) throw new Error("trusted root certificate rawBytes is empty");
      return der;
    })
    .reverse();
  return { chainDer, ...validity(o) };
}

/** A log: its key imported for verification, the id entries name it by, and its validity window. */
async function keyedAuthority(o: JsonObject): Promise<KeyedAuthority> {
  const hashAlgorithm = str(o, "hashAlgorithm");
  if (hashAlgorithm !== "SHA2_256") {
    throw new Error(`unsupported transparency log hash algorithm ${JSON.stringify(hashAlgorithm)}`);
  }
  const key = struct(o, "publicKey", PUBLIC_KEY_MEMBERS);
  const spki = decodeBase64("publicKey rawBytes", str(key, "rawBytes"));
  if (spki.length === 0) throw new Error("transparency log public key is empty");
  const keyDetails = str(key, "keyDetails");
  const algorithm = KEY_ALGORITHMS[keyDetails];
  if (algorithm === undefined) throw new Error(`unsupported transparency log key type ${JSON.stringify(keyDetails)}`);
  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey("spki", spki as Uint8Array<ArrayBuffer>, algorithm, true, ["verify"]);
  } catch (err) {
    throw new Error(`importing transparency log key: ${(err as Error).message}`);
  }
  // The log id is SHA-256 of the key for every log that leaves it implicit; a
  // log that states one (some newer logs derive it differently) is named by
  // what it states, since that is what its entries carry.
  const stated = optStruct(o, "logId", LOG_ID_MEMBERS);
  const keyId = stated === undefined ? "" : str(stated, "keyId");
  const logId = keyId === "" ? toHex(await sha256(spki)) : toHex(decodeBase64("logId keyId", keyId));
  if (logId.length !== 64) throw new Error("transparency log id is not 32 bytes");
  return { logId, publicKey, ...validity(key) };
}

/** The `validFor` window: `start` is required, `end` optional, both RFC 3339. */
function validity(o: JsonObject): { validFrom: Date; validTo?: Date } {
  const window = struct(o, "validFor", VALIDITY_MEMBERS);
  const start = str(window, "start");
  if (start === "") throw new Error("trusted root validity window has no start");
  const validFrom = timestamp(start);
  const end = str(window, "end");
  if (end === "") return { validFrom };
  const validTo = timestamp(end);
  if (validTo.getTime() < validFrom.getTime()) throw new Error("trusted root validity window ends before it starts");
  return { validFrom, validTo };
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/** An RFC 3339 time; the calendar date must exist and the clock fields must be in range. */
function timestamp(s: string): Date {
  const m = RFC3339.exec(s);
  const d = new Date(s);
  if (m === null || Number.isNaN(d.getTime())) throw new Error(`trusted root time ${JSON.stringify(s)} is not RFC 3339`);
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  // Date.UTC rolls an impossible day into the next month; a real date reads back unchanged.
  const probe = new Date(Date.UTC(year, month - 1, day));
  if (probe.getUTCFullYear() !== year || probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59) {
    throw new Error(`trusted root time ${JSON.stringify(s)} is not a real time`);
  }
  return d;
}
