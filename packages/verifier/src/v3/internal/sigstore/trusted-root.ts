/**
 * The Sigstore trusted root: certificate authorities, transparency logs,
 * certificate-transparency logs and timestamp authorities, each with a
 * validity window.
 */
import { notImplemented } from "../../errors.js";
import type { JsonValue } from "../json/index.js";

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

/** Parses trusted-root JSON (media type trustedroot+json version 0.1). */
export async function parseTrustedRoot(json: Uint8Array): Promise<TrustedRoot> {
  return notImplemented("sigstore.parseTrustedRoot");
}

/** The embedded production trusted root. */
export async function embeddedTrustedRoot(): Promise<TrustedRoot> {
  return notImplemented("sigstore.embeddedTrustedRoot");
}
