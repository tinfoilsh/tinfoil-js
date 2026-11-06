/**
 * The identity check a pinned connection runs in its TLS handshake, after
 * the runtime's own certificate check: the peer's leaf certificate must
 * carry the attested key, compared by the SHA-256 of its SubjectPublicKeyInfo,
 * and the certificate must still pass the normal hostname check. Node and
 * Bun only: it reads the certificate the runtime exposes during the
 * handshake, which browsers never do, so only modules the browser build maps
 * away import it.
 */
import { CERT_MISMATCH } from "./pin-errors.js";
import { PeerLacksKeyError } from "./transport.js";

type PeerCertificate = import("node:tls").PeerCertificate;

/** A function the runtime calls with the peer's certificate; undefined accepts the peer, an error rejects it. */
export type IdentityCheck = (host: string, cert: PeerCertificate) => Error | undefined;

/**
 * The check for `key`, the attested SPKI fingerprint. A peer whose
 * certificate carries another key, or no certificate at all, is a
 * {@link PeerLacksKeyError}; a certificate carrying the key still has to
 * name the host.
 */
export async function identityCheck(key: string): Promise<IdentityCheck> {
  const [tls, { X509Certificate, createHash }] = await Promise.all([import("node:tls"), import("node:crypto")]);
  return (host, cert) => {
    const raw = cert?.raw;
    if (raw === undefined) return new PeerLacksKeyError("the peer presented no certificate");
    const spki = new X509Certificate(raw).publicKey.export({ type: "spki", format: "der" });
    const fingerprint = createHash("sha256").update(spki).digest("hex");
    if (fingerprint !== key) return new PeerLacksKeyError(CERT_MISMATCH);
    return tls.checkServerIdentity(host, cert);
  };
}
