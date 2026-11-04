/**
 * The identity check a pinned connection runs in its TLS handshake, after
 * the runtime's own certificate check: the peer's leaf certificate must
 * carry the attested key, compared by the SHA-256 of its SubjectPublicKeyInfo,
 * and the certificate must still pass the normal hostname check. Node and
 * Bun only: it reads the certificate the runtime exposes during the
 * handshake, which browsers never do.
 */
import { PeerLacksKeyError } from "./transport.js";

export const CERT_MISMATCH = "enclave certificate does not match the attested key; re-verify the enclave";

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

/** Whether a connection error means the peer's certificate failed the normal check or the pin. */
export function isCertificateError(err: unknown): boolean {
  if (err instanceof PeerLacksKeyError) return true;
  const code = (err as { code?: unknown })?.code;
  if (typeof code !== "string") return false;
  return (
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    code === "HOSTNAME_MISMATCH" ||
    code.startsWith("CERT_") ||
    code.startsWith("UNABLE_TO_") ||
    code.startsWith("DEPTH_ZERO_") ||
    code.startsWith("SELF_SIGNED_")
  );
}
