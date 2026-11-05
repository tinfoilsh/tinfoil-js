/**
 * The TLS transport mode in a browser: unavailable, since a browser exposes
 * nothing of the TLS connection to pin. Selecting it is a configuration
 * error; browsers use the EHBP mode.
 */
import { ConfigurationError } from "../../errors.js";
import type { Mode } from "./transport.js";

export interface TLSOptions {
  readonly ca?: string | Uint8Array;
}

export function tlsMode(_options: TLSOptions = {}): Mode {
  throw new ConfigurationError("TLS transport mode is not available in browsers; use the EHBP transport mode");
}
