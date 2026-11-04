/**
 * WARNING: THIS CLIENT IS INSECURE.
 *
 * An EHBP client whose key comes straight from the server, with no
 * attestation: whoever answers the key request decides what the bodies are
 * sealed to, so a server in the middle can read them. It exists to exercise
 * the EHBP protocol against a local development server that has no
 * attestation set up. Anything that handles real data uses the attested
 * clients of the package's main entry.
 *
 * The client keeps the attested clients' request rules where they still
 * apply: bodies are sealed to the fetched key, requests stay on the base
 * URL's origin, a proxy in front is told which server the request is for,
 * and plaintext HTTP is accepted only to a loopback host. Nothing verifies
 * the key, so nothing is re-verified either: a key the server no longer
 * holds surfaces as the server's own error.
 */
import { Identity, PROTOCOL } from "ehbp";
import { ConfigurationError, messageOf, NetworkError } from "../errors.js";
import { validateBaseURL } from "./transport/base-url.js";
import { sealedFetchTo } from "./transport/ehbp.js";
import { ENCLAVE_URL_HEADER } from "./transport/header.js";
import { normalizedOrigin, originOf, requestURL } from "./transport/origin.js";
import type { Fetch } from "../options.js";

/** Configures an {@link UnverifiedClient}. At least one of `baseURL` and `keyOrigin` is required. */
export interface UnverifiedOptions {
  /**
   * Where requests go. Defaults to the key origin's `/v1/`. A relative request
   * URL is resolved against it. HTTPS, or HTTP only to localhost or a loopback
   * IP address.
   */
  readonly baseURL?: string;
  /**
   * The origin whose `/.well-known/hpke-keys` supplies the sealing key.
   * Defaults to the base URL's origin. When it differs from the base URL's
   * origin, the base URL is a proxy and requests carry `X-Tinfoil-Enclave-Url`
   * naming this origin.
   */
  readonly keyOrigin?: string;
  /** Aborts the key fetch the factory performs before it returns. */
  readonly signal?: AbortSignal;
}

/** Seams for tests: the fetch used for the key and for requests, and where the warning goes. */
export interface UnverifiedClientSeams {
  readonly fetch?: Fetch;
  readonly warn?: (message: string) => void;
}

/** Logged once per client created, so an unverified client is never silent. */
export const UNVERIFIED_WARNING =
  "[tinfoil] WARNING: UnverifiedClient is insecure. The HPKE key is fetched from the server without attestation verification. Only use for local development and testing of the EHBP protocol.";

const MAX_KEY_CONFIG_BYTES = 64 * 1024;

/** Marks construction by this module's factory; the constructor refuses anything else. */
const TOKEN = Symbol("UnverifiedClient");

/** The option checks that need no network I/O. */
export function checkUnverifiedOptions(options: UnverifiedOptions): { baseURL: string; keyOrigin: string } {
  if (options.baseURL === undefined && options.keyOrigin === undefined) {
    throw new ConfigurationError("UnverifiedClient needs a baseURL or a keyOrigin; it never discovers a server by itself");
  }
  const keySource = options.keyOrigin ?? options.baseURL!;
  checkURL(keySource);
  const keyOrigin = originOf(keySource);
  const baseURL = options.baseURL ?? `${keyOrigin}/v1/`;
  checkURL(baseURL);
  return { baseURL, keyOrigin };
}

/** HTTPS or loopback HTTP, as for a base URL, and no credentials, which the key fetch and the requests would otherwise send. */
function checkURL(url: string): void {
  validateBaseURL(url);
  const u = new URL(url);
  if (u.username !== "" || u.password !== "") throw new ConfigurationError(`URL must not carry credentials: ${JSON.stringify(url)}`);
}

/** The factory with its test seams; {@link UnverifiedClient.create} is this without them. */
export async function createUnverifiedClient(options: UnverifiedOptions, seams: UnverifiedClientSeams): Promise<UnverifiedClient> {
  const { baseURL, keyOrigin } = checkUnverifiedOptions(options);
  (seams.warn ?? ((message: string) => console.warn(message)))(UNVERIFIED_WARNING);
  const send: Fetch = seams.fetch ?? ((input, init) => fetch(input, init));
  const identity = await fetchUnverifiedKey(keyOrigin, send, options.signal);
  const sealed = sealedFetchTo(identity, send);
  const baseOrigin = originOf(baseURL);
  const proxied = baseOrigin !== keyOrigin;
  const fetchImpl: Fetch = (input, init) => {
    const url = input instanceof Request ? requestURL(input) : new URL(input instanceof URL ? input.href : input, baseURL);
    const origin = normalizedOrigin(url);
    if (origin !== baseOrigin) {
      return Promise.reject(new ConfigurationError(`refusing to send request to ${JSON.stringify(origin)}: client is bound to ${JSON.stringify(baseOrigin)}`));
    }
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    if (proxied) headers.set(ENCLAVE_URL_HEADER, keyOrigin);
    const target = input instanceof Request ? input : url;
    return sealed.fetch(target, { ...init, headers });
  };
  return new UnverifiedClient(TOKEN, baseURL, keyOrigin, fetchImpl);
}

/** The server's key configuration from `keyOrigin`, taken on trust. */
async function fetchUnverifiedKey(keyOrigin: string, send: Fetch, signal: AbortSignal | undefined): Promise<Identity> {
  let response: Response;
  try {
    response = await send(`${keyOrigin}${PROTOCOL.KEYS_PATH}`, { method: "GET", signal });
  } catch (err) {
    if (signal?.aborted) throw err;
    throw new NetworkError(`fetching the server key: ${messageOf(err)}`, { cause: err });
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new NetworkError(`fetching the server key: status ${response.status}`);
  }
  const contentType = response.headers.get("content-type");
  if (contentType === null || contentType.split(";", 1)[0]!.trim().toLowerCase() !== PROTOCOL.KEYS_MEDIA_TYPE) {
    await response.body?.cancel().catch(() => {});
    throw new NetworkError(`fetching the server key: content type ${JSON.stringify(contentType)} is not ${PROTOCOL.KEYS_MEDIA_TYPE}`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > MAX_KEY_CONFIG_BYTES) throw new NetworkError(`fetching the server key: configuration exceeds ${MAX_KEY_CONFIG_BYTES} bytes`);
  try {
    return await Identity.unmarshalPublicConfig(bytes);
  } catch (err) {
    throw new NetworkError(`fetching the server key: ${messageOf(err)}`, { cause: err });
  }
}

/**
 * INSECURE: seals bodies to whatever key the server hands out, with no
 * attestation. For local development against a server without attestation
 * only; see the module header.
 */
export class UnverifiedClient {
  /**
   * Sends a request with its body sealed to the fetched key. A relative URL
   * is resolved against the base URL; a request to another origin is a
   * {@link ConfigurationError}.
   */
  readonly fetch: Fetch;
  readonly #baseURL: string;
  readonly #keyOrigin: string;

  /** @internal Only {@link create} constructs a client; anything else is refused. */
  constructor(token: symbol, baseURL: string, keyOrigin: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("UnverifiedClient is created with UnverifiedClient.create");
    this.#baseURL = baseURL;
    this.#keyOrigin = keyOrigin;
    this.fetch = fetchImpl;
  }

  /**
   * A client sealing to the key `keyOrigin` serves, with requests going to
   * `baseURL`. Logs a warning: nothing checks that the key belongs to an
   * enclave. Options are checked before any network I/O; the key is fetched
   * before the client is returned.
   */
  static create(options?: UnverifiedOptions): Promise<UnverifiedClient> {
    return createUnverifiedClient(options ?? {}, {});
  }

  /** Where requests go. */
  baseURL(): string {
    return this.#baseURL;
  }

  /** The origin the sealing key was fetched from. */
  keyOrigin(): string {
    return this.#keyOrigin;
  }
}
