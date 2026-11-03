/** X.509 certificate revocation lists. */
import { notImplemented } from "../../errors.js";
import type { Certificate, SignatureAlgorithm } from "./certificate.js";

export interface RevocationList {
  readonly raw: Uint8Array;
  readonly tbs: Uint8Array;
  readonly issuer: Uint8Array;
  readonly thisUpdate: Date;
  /** Required: a CRL without a next-update time rejects. */
  readonly nextUpdate: Date;
  readonly revokedSerials: readonly bigint[];
  readonly signatureAlgorithm: SignatureAlgorithm;
  readonly signature: Uint8Array;
}

export function parseRevocationList(der: Uint8Array): RevocationList {
  return notImplemented("x509.parseRevocationList");
}

/** Verifies the CRL's signature with the issuer's key and that `at` lies within [thisUpdate, nextUpdate]. */
export async function verifyRevocationList(crl: RevocationList, issuer: Certificate, at: Date): Promise<void> {
  return notImplemented("x509.verifyRevocationList");
}

export function isRevoked(crl: RevocationList, serial: bigint): boolean {
  return notImplemented("x509.isRevoked");
}
