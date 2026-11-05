/**
 * Session recovery for sealed exchanges. A response obtained through a
 * client in the `"ehbp"` transport mode was sealed to the enclave's key and
 * opened with the secret of its own exchange. That secret can be exported
 * as a token: plain bytes that let any holder open the same sealed response
 * later, after the client that sent the request is gone, for example a
 * browser that takes over a stream a server started. A token opens one
 * response only, so it carries no lasting authority; still, hand it only to
 * the party that should read that response.
 */
import { extractSessionRecoveryToken, type SessionRecoveryToken } from "ehbp";
import { ConfigurationError } from "./errors.js";
import { recoveryContextOf } from "./internal/transport/ehbp.js";

export type { SessionRecoveryToken } from "ehbp";
export { serializeSessionRecoveryToken, deserializeSessionRecoveryToken, decryptResponseWithToken } from "ehbp";

/**
 * The session recovery token of `response`: the one a client's `fetch`
 * returned for a request whose body was sealed in the `"ehbp"` transport
 * mode. A response that was not sealed (a bodyless request, a plaintext
 * error from a proxy, or any response in the `"tls"` mode) has none and is a
 * {@link ConfigurationError}. The token opens the sealed form of this
 * response, as a relay forwards it, with
 * {@link decryptResponseWithToken}; serialize it with
 * {@link serializeSessionRecoveryToken}.
 */
export async function sessionRecoveryToken(response: Response): Promise<SessionRecoveryToken> {
  const context = recoveryContextOf(response);
  if (context === undefined) {
    throw new ConfigurationError("response was not opened from a sealed exchange; only a sealed response in the \"ehbp\" transport mode has a session recovery token");
  }
  return extractSessionRecoveryToken(context);
}
