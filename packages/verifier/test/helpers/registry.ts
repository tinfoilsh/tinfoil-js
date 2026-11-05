/**
 * A synthetic config registry for tests: a self-signed P-256 root whose key
 * is pinned as a registry root, and the short-lived scope certificates it
 * issues to approval signing keys. DER is built by hand; the verifier's own
 * decoder is what checks it.
 */
import { utf8 } from "../../src/internal/bytes.js";
import { newSigner, type Signer } from "./keyed.js";
import { bitString, boolTrue, certificate, extension, integer, name, oid, seq, tlv } from "./tsa.js";

const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_SUBJECT_ALT_NAME = "2.5.29.17";
export const OID_KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
export const OID_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

const HOUR_MS = 60 * 60 * 1000;
const MINUTE_MS = 60 * 1000;

/** A GeneralName uniformResourceIdentifier: [6] IMPLICIT IA5String. */
export const uriName = (uri: string): Uint8Array => tlv(0x86, utf8(uri));
/** A GeneralName dNSName: [2] IMPLICIT IA5String. */
export const dnsName = (host: string): Uint8Array => tlv(0x82, utf8(host));

export interface Registry {
  /** The root key; its PEM is pinned as a registry root and it signs the scope certificates. */
  readonly root: Signer;
  readonly rootName: Uint8Array;
  readonly rootDer: Uint8Array;
  readonly notBefore: Date;
  readonly notAfter: Date;
}

/** A self-signed registry root (CA, path length 0, keyCertSign and digitalSignature) valid from an hour before `now` for a year. */
export async function newRegistry(now: Date): Promise<Registry> {
  const root = await newSigner();
  const rootName = name("registry test root");
  const notBefore = new Date(now.getTime() - HOUR_MS);
  const notAfter = new Date(now.getTime() + 365 * 24 * HOUR_MS);
  const rootDer = await certificate(
    {
      subject: rootName,
      issuer: rootName,
      serial: 1,
      notBefore,
      notAfter,
      spki: root.spki,
      extensions: [
        extension(OID_BASIC_CONSTRAINTS, true, seq(boolTrue(), integer(0))),
        extension(OID_KEY_USAGE, true, tlv(0x03, [0x02, 0x84])), // digitalSignature, keyCertSign
      ],
    },
    root.pair.privateKey,
  );
  return { root, rootName, rootDer, notBefore, notAfter };
}

export interface ScopeCertificateOptions {
  readonly scope: string;
  /** The leaf is valid from a minute before `now` to nine minutes after it. */
  readonly now: Date;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  /** Replace the basicConstraints value (default: not a CA). */
  readonly basicConstraints?: Uint8Array;
  /** Replace the key usage BIT STRING (default: digitalSignature). */
  readonly keyUsage?: Uint8Array;
  /** Replace the extended key usage purposes (default: code signing only); "none" omits the extension. */
  readonly extendedKeyUsage?: readonly string[] | "none";
  /** Replace the subject (default: empty). */
  readonly subject?: Uint8Array;
  /** Replace the SAN's GeneralNames (default: one URI naming the scope); "none" omits the extension. */
  readonly subjectAltNames?: readonly Uint8Array[] | "none";
  readonly sanCritical?: boolean;
  /** Further extensions appended as is. */
  readonly extraExtensions?: readonly Uint8Array[];
}

/** A scope certificate over `spki`, issued by `registry`, fitting the signing profile unless an option departs from it. */
export async function scopeCertificate(registry: Registry, spki: Uint8Array, opts: ScopeCertificateOptions): Promise<Uint8Array> {
  const extensions: Uint8Array[] = [
    extension(OID_BASIC_CONSTRAINTS, true, opts.basicConstraints ?? seq()),
    extension(OID_KEY_USAGE, true, opts.keyUsage ?? tlv(0x03, [0x07, 0x80])),
  ];
  const eku = opts.extendedKeyUsage ?? [OID_KP_CODE_SIGNING];
  if (eku !== "none") extensions.push(extension(OID_EXT_KEY_USAGE, false, seq(...eku.map(oid))));
  const sans = opts.subjectAltNames ?? [uriName(opts.scope)];
  if (sans !== "none") extensions.push(extension(OID_SUBJECT_ALT_NAME, opts.sanCritical ?? true, seq(...sans)));
  extensions.push(...(opts.extraExtensions ?? []));
  return certificate(
    {
      subject: opts.subject ?? seq(),
      issuer: registry.rootName,
      serial: 7,
      notBefore: opts.notBefore ?? new Date(opts.now.getTime() - MINUTE_MS),
      notAfter: opts.notAfter ?? new Date(opts.now.getTime() + 9 * MINUTE_MS),
      spki,
      extensions,
    },
    registry.root.pair.privateKey,
  );
}

export { bitString };
