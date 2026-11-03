/** X.509 certificate revocation lists. */
import {
  bytesEqual,
  canSignRevocationLists,
  expectSequence,
  isContext,
  isUniversal,
  signatureAlgorithm,
  verifySignatureWith,
  withContext,
  X509Error,
  type Certificate,
  type SignatureAlgorithm,
} from "./certificate.js";
import { bitString, children, decode, integer, TAG, time, type DerElement } from "./der.js";

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

function isTime(e: DerElement): boolean {
  return isUniversal(e, TAG.UTC_TIME) || isUniversal(e, TAG.GENERALIZED_TIME);
}

function parseRevokedSerials(list: DerElement): bigint[] {
  const out: bigint[] = [];
  for (const entry of expectSequence(list, "revokedCertificates")) {
    const parts = expectSequence(entry, "revoked certificate entry");
    if (parts.length < 2 || parts.length > 3) throw new X509Error("revoked certificate entry must hold a serial, a date and optional extensions");
    out.push(integer(parts[0]));
    time(parts[1]);
    if (parts.length === 3) expectSequence(parts[2], "CRL entry extensions");
  }
  return out;
}

export function parseRevocationList(der: Uint8Array): RevocationList {
  return withContext("revocation list", () => {
    const top = expectSequence(decode(der), "CertificateList");
    if (top.length !== 3) throw new X509Error("CertificateList must hold tbsCertList, signatureAlgorithm and signatureValue");
    const [tbsEl, outerAlg, sigEl] = top;
    const tbs = expectSequence(tbsEl, "TBSCertList");
    let i = 0;
    let version = 0n;
    if (tbs.length > 0 && isUniversal(tbs[0], TAG.INTEGER)) {
      version = integer(tbs[0]);
      if (version !== 1n) throw new X509Error(`unsupported revocation list version ${version + 1n}`);
      i = 1;
    }
    if (tbs.length < i + 3) throw new X509Error("TBSCertList is missing required fields");
    const innerAlg = tbs[i];
    const issuerEl = tbs[i + 1];
    expectSequence(issuerEl, "issuer Name");
    const thisUpdate = time(tbs[i + 2]);
    let j = i + 3;
    if (j >= tbs.length || !isTime(tbs[j])) throw new X509Error("nextUpdate is required");
    const nextUpdate = time(tbs[j]);
    j++;
    let revokedSerials: bigint[] = [];
    if (j < tbs.length && isUniversal(tbs[j], TAG.SEQUENCE)) {
      revokedSerials = parseRevokedSerials(tbs[j]);
      j++;
    }
    if (j < tbs.length && isContext(tbs[j], 0) && tbs[j].constructed) {
      if (version !== 1n) throw new X509Error("CRL extensions require version 2");
      const inner = children(tbs[j]);
      if (inner.length !== 1) throw new X509Error("CRL extensions must wrap one SEQUENCE");
      expectSequence(inner[0], "CRL extensions");
      j++;
    }
    if (j !== tbs.length) throw new X509Error("unexpected field in TBSCertList");
    if (!bytesEqual(innerAlg.raw, outerAlg.raw)) throw new X509Error("inner and outer signature algorithms differ");
    if (thisUpdate.getTime() > nextUpdate.getTime()) throw new X509Error("thisUpdate is after nextUpdate");
    return {
      raw: der,
      tbs: tbsEl.raw,
      issuer: issuerEl.raw,
      thisUpdate,
      nextUpdate,
      revokedSerials,
      signatureAlgorithm: signatureAlgorithm(outerAlg),
      signature: bitString(sigEl),
    };
  });
}

/** Verifies the CRL's signature with the issuer's key and that `at` lies within [thisUpdate, nextUpdate]. */
export async function verifyRevocationList(crl: RevocationList, issuer: Certificate, at: Date): Promise<void> {
  if (Number.isNaN(at.getTime())) throw new X509Error("verification time is invalid");
  if (!bytesEqual(crl.issuer, issuer.subject)) throw new X509Error("revocation list issuer does not match the issuing certificate");
  if (!canSignRevocationLists(issuer)) throw new X509Error("issuing certificate may not sign revocation lists");
  if (!(await verifySignatureWith(crl.signatureAlgorithm, crl.tbs, crl.signature, issuer.spki))) {
    throw new X509Error("revocation list signature does not verify");
  }
  const t = at.getTime();
  if (t < crl.thisUpdate.getTime() || t > crl.nextUpdate.getTime()) {
    throw new X509Error(
      `revocation list is not current at ${at.toISOString()} (thisUpdate ${crl.thisUpdate.toISOString()}, nextUpdate ${crl.nextUpdate.toISOString()})`,
    );
  }
}

export function isRevoked(crl: RevocationList, serial: bigint): boolean {
  return crl.revokedSerials.some((s) => s === serial);
}
