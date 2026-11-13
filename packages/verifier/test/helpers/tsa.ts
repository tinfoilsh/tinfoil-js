/**
 * A synthetic RFC 3161 timestamp authority for tests: a self-signed P-256
 * root, a timestamping leaf it issued (critical key usage digitalSignature,
 * critical extended key usage of timestamping only), and TimeStampResp
 * minting over arbitrary input at a chosen genTime. The chain is returned in
 * trusted-root wire order (leaf first, root last).
 *
 * DER is built by hand here; the verifier's own decoder is what checks it.
 */
import { sha256, utf8 } from "../../src/internal/bytes.js";
import { b64, derSignature, P256 } from "./keyed.js";

// ---------------------------------------------------------------- DER encoding

function len(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return [0x80 | out.length, ...out];
}

export function tlv(tag: number, ...content: (Uint8Array | number[])[]): Uint8Array {
  const body = content.flatMap((c) => Array.from(c));
  return new Uint8Array([tag, ...len(body.length), ...body]);
}

export const seq = (...parts: Uint8Array[]): Uint8Array => tlv(0x30, ...parts);
export const set = (...parts: Uint8Array[]): Uint8Array => tlv(0x31, ...parts);
export const octetString = (b: Uint8Array): Uint8Array => tlv(0x04, b);
export const explicit = (n: number, inner: Uint8Array): Uint8Array => tlv(0xa0 | n, inner);
export const implicitConstructed = (n: number, inner: Uint8Array): Uint8Array => new Uint8Array([0xa0 | n, ...inner.subarray(1)]);
export const boolTrue = (): Uint8Array => tlv(0x01, [0xff]);
export const nullValue = (): Uint8Array => tlv(0x05, []);
export const utf8String = (s: string): Uint8Array => tlv(0x0c, utf8(s));

/** A non-negative INTEGER in minimal two's-complement form. */
export function integer(n: number | bigint): Uint8Array {
  let v = BigInt(n);
  const bytes: number[] = [];
  do {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v > 0n);
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return tlv(0x02, bytes);
}

/** An OBJECT IDENTIFIER: the first two arcs combine into one sub-identifier, and every sub-identifier is base-128 encoded. */
export function oid(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map(Number);
  const body: number[] = [];
  for (const sub of [40 * arcs[0]! + arcs[1]!, ...arcs.slice(2)]) {
    const groups: number[] = [];
    let v = sub;
    do {
      groups.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < groups.length - 1; i++) groups[i]! |= 0x80;
    body.push(...groups);
  }
  return tlv(0x06, body);
}

/** A BIT STRING with no unused bits. */
export const bitString = (b: Uint8Array): Uint8Array => tlv(0x03, [0], b);

/** UTCTime "YYMMDDHHMMSSZ". */
export function utcTime(d: Date): Uint8Array {
  const s = d.toISOString(); // YYYY-MM-DDTHH:MM:SS.sssZ
  return tlv(0x17, utf8(`${s.slice(2, 4)}${s.slice(5, 7)}${s.slice(8, 10)}${s.slice(11, 13)}${s.slice(14, 16)}${s.slice(17, 19)}Z`));
}

/** GeneralizedTime "YYYYMMDDHHMMSSZ", whole seconds. */
export function generalizedTime(d: Date): Uint8Array {
  const s = d.toISOString();
  return tlv(0x18, utf8(`${s.slice(0, 4)}${s.slice(5, 7)}${s.slice(8, 10)}${s.slice(11, 13)}${s.slice(14, 16)}${s.slice(17, 19)}Z`));
}

/** The certificate Time choice: UTCTime for 1950 through 2049, which is all that its two-digit year can name, GeneralizedTime otherwise. */
export function validityTime(d: Date): Uint8Array {
  const year = d.getUTCFullYear();
  return year >= 1950 && year <= 2049 ? utcTime(d) : generalizedTime(d);
}

/** A Name of one commonName and one organizationName RDN. */
export function name(commonName: string, organization = "tinfoil-js test"): Uint8Array {
  const rdn = (type: string, value: string): Uint8Array => set(seq(oid(type), utf8String(value)));
  return seq(rdn("2.5.4.3", commonName), rdn("2.5.4.10", organization));
}

const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
export const SIGSTORE_TIMESTAMP_POLICY = "1.3.6.1.4.1.57264.2";

const ecdsaWithSha256 = (): Uint8Array => seq(oid(OID_ECDSA_WITH_SHA256));
const sha256AlgId = (): Uint8Array => seq(oid(OID_SHA256), nullValue());

export function extension(id: string, critical: boolean, value: Uint8Array): Uint8Array {
  return seq(oid(id), ...(critical ? [boolTrue()] : []), octetString(value));
}

async function signP256Der(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return derSignature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data as Uint8Array<ArrayBuffer>)));
}

// ---------------------------------------------------------------- certificates

export interface CertificateSpec {
  readonly subject: Uint8Array;
  readonly issuer: Uint8Array;
  readonly serial: number;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly spki: Uint8Array;
  readonly extensions: readonly Uint8Array[];
}

/** A v3 certificate over `spec`, signed with `issuerKey` (ecdsa-with-SHA256). */
export async function certificate(spec: CertificateSpec, issuerKey: CryptoKey): Promise<Uint8Array> {
  const tbs = seq(
    explicit(0, integer(2)),
    integer(spec.serial),
    ecdsaWithSha256(),
    spec.issuer,
    seq(validityTime(spec.notBefore), validityTime(spec.notAfter)),
    spec.subject,
    spec.spki,
    explicit(3, seq(...spec.extensions)),
  );
  return seq(tbs, ecdsaWithSha256(), bitString(await signP256Der(issuerKey, tbs)));
}

export interface TimestampAuthority {
  readonly rootKey: CryptoKeyPair;
  readonly leafKey: CryptoKeyPair;
  readonly rootDer: Uint8Array;
  readonly leafDer: Uint8Array;
  /** Leaf first, root last. */
  readonly chainDer: readonly Uint8Array[];
  readonly leafSerial: number;
  readonly leafIssuer: Uint8Array;
}

export interface AuthorityOptions {
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  /** Omit the leaf's extended key usage, or make it non-critical. */
  readonly eku?: "critical" | "non-critical" | "none";
  /** Key usage bits of the leaf as a BIT STRING body; defaults to digitalSignature. */
  readonly leafKeyUsage?: Uint8Array;
}

/** A self-signed root and the timestamping leaf it issued, valid over 2025 by default. */
export async function newTimestampAuthority(opts: AuthorityOptions = {}): Promise<TimestampAuthority> {
  const notBefore = opts.notBefore ?? new Date("2025-01-01T00:00:00Z");
  const notAfter = opts.notAfter ?? new Date("2026-01-01T00:00:00Z");
  const rootKey = await crypto.subtle.generateKey(P256, true, ["sign", "verify"]);
  const leafKey = await crypto.subtle.generateKey(P256, true, ["sign", "verify"]);
  const rootName = name("tinfoil-js test TSA root");
  const leafName = name("tinfoil-js test TSA signer");
  const rootDer = await certificate(
    {
      subject: rootName,
      issuer: rootName,
      serial: 1,
      notBefore,
      notAfter,
      spki: new Uint8Array(await crypto.subtle.exportKey("spki", rootKey.publicKey)),
      extensions: [
        extension(OID_BASIC_CONSTRAINTS, true, seq(boolTrue())),
        extension(OID_KEY_USAGE, true, tlv(0x03, [0x01, 0x06])), // keyCertSign, cRLSign
      ],
    },
    rootKey.privateKey,
  );
  const eku = opts.eku ?? "critical";
  const leafExtensions = [extension(OID_KEY_USAGE, true, opts.leafKeyUsage ?? tlv(0x03, [0x07, 0x80]))];
  if (eku !== "none") leafExtensions.push(extension(OID_EXT_KEY_USAGE, eku === "critical", seq(oid(OID_KP_TIMESTAMPING))));
  const leafDer = await certificate(
    {
      subject: leafName,
      issuer: rootName,
      serial: 2,
      notBefore,
      notAfter,
      spki: new Uint8Array(await crypto.subtle.exportKey("spki", leafKey.publicKey)),
      extensions: leafExtensions,
    },
    rootKey.privateKey,
  );
  return { rootKey, leafKey, rootDer, leafDer, chainDer: [leafDer, rootDer], leafSerial: 2, leafIssuer: rootName };
}

/** The trusted-root `timestampAuthorities` entry for `tsa`, as rootJson's AuthorityJson. */
export function authorityJson(tsa: TimestampAuthority, start = "2025-01-01T00:00:00Z", end?: string): { certificates: string[]; start: string; end?: string } {
  return { certificates: tsa.chainDer.map(b64), start, ...(end === undefined ? {} : { end }) };
}

// ---------------------------------------------------------------- responses

export interface ResponseOptions {
  readonly policy?: string;
  readonly status?: number;
  readonly serial?: number;
  /** The message imprint to state instead of SHA-256 of the input. */
  readonly imprint?: Uint8Array;
  readonly certificateBinding?: "valid" | "missing" | "wrong";
}

/** TSTInfo ::= SEQUENCE { version 1, policy, messageImprint, serialNumber, genTime }. */
export function tstInfo(imprint: Uint8Array, genTime: Date, opts: ResponseOptions = {}): Uint8Array {
  return seq(
    integer(1),
    oid(opts.policy ?? SIGSTORE_TIMESTAMP_POLICY),
    seq(sha256AlgId(), octetString(imprint)),
    integer(opts.serial ?? 1),
    generalizedTime(genTime),
  );
}

/** A granted TimeStampResp over SHA-256 of `input` at `genTime`, signed by the authority's leaf. */
export async function timestampResponse(tsa: TimestampAuthority, input: Uint8Array, genTime: Date, opts: ResponseOptions = {}): Promise<Uint8Array> {
  const info = tstInfo(opts.imprint ?? (await sha256(input)), genTime, opts);
  const signedAttrs = [
    seq(oid(OID_CONTENT_TYPE), set(oid(OID_TST_INFO))),
    seq(oid(OID_MESSAGE_DIGEST), set(octetString(await sha256(info)))),
  ];
  if (opts.certificateBinding !== "missing") {
    const digest = await sha256(tsa.leafDer);
    if (opts.certificateBinding === "wrong") digest[0] ^= 1;
    signedAttrs.push(seq(oid(OID_SIGNING_CERTIFICATE_V2), set(seq(seq(seq(octetString(digest)))))));
  }
  const attrsSet = set(...signedAttrs);
  const signature = await signP256Der(tsa.leafKey.privateKey, attrsSet);
  const signerInfo = seq(
    integer(1),
    seq(tsa.leafIssuer, integer(tsa.leafSerial)),
    sha256AlgId(),
    implicitConstructed(0, attrsSet),
    ecdsaWithSha256(),
    octetString(signature),
  );
  const signedData = seq(
    integer(3),
    set(sha256AlgId()),
    seq(oid(OID_TST_INFO), explicit(0, octetString(info))),
    // certificates [0] IMPLICIT CertificateSet: a SET OF Certificate under the implicit tag.
    implicitConstructed(0, set(tsa.leafDer)),
    set(signerInfo),
  );
  const token = seq(oid(OID_SIGNED_DATA), explicit(0, signedData));
  return seq(seq(integer(opts.status ?? 0)), token);
}
