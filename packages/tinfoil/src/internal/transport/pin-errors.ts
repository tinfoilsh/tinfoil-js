/**
 * How a pinned connection's failures are recognised, shared by the TLS
 * transport mode and pinned WebSockets. This module reads nothing of the
 * runtime, so it is safe in every build; the identity check itself, which
 * needs the runtime's TLS and certificate support, lives in a module the
 * browser build maps away.
 */
import { PeerLacksKeyError } from "./transport.js";

export const CERT_MISMATCH = "enclave certificate does not match the attested key; re-verify the enclave";

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
