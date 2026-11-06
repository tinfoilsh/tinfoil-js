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
import { ConfigurationError, messageOf, NetworkError, TinfoilError } from "../errors.js";
import { readBounded } from "./fetch.js";
import { normalizeBaseURL, validateBaseURL } from "./transport/base-url.js";
import { sealedFetchTo } from "./transport/ehbp.js";
import { ENCLAVE_URL_HEADER } from "./transport/header.js";
import { normalizedOrigin, originOf, requestURL } from "./transport/origin.js";
import type { Fetch } from "../options.js";

/** Configures an {@link UnverifiedClient}. At least one of `baseURL` and `keyOrigin` is required. */
export interface UnverifiedOptions {
  /**
   * Where requests go. Defaults to the key origin's `/v1/`. A relative request
   * URL is resolved against it, so it is made to end with `/`. HTTPS, or HTTP
   * only to localhost or a loopback IP address.
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

/** @internal Seams for tests: the fetch used for the key and for requests, and where the warning goes. */
export interface UnverifiedClientSeams {
  readonly fetch?: Fetch;
  readonly warn?: (message: string) => void;
}

/** Logged once per client created, so an unverified client is never silent. */
export const UNVERIFIED_WARNING =
  "[tinfoil] WARNING: UnverifiedClient is insecure. The HPKE key is fetched from the server without attestation verification. Only use for local development and testing of the EHBP protocol.";

const MAX_KEY_CONFIG_BYTES = 64 * 1024;

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const TOKEN: unique symbol = Symbol("UnverifiedClient");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (baseURL: string, keyOrigin: string, fetchImpl: Fetch) => UnverifiedClient;

/** @internal The option checks that need no network I/O. The base URL comes back ending with `/`. */
export function checkUnverifiedOptions(options: UnverifiedOptions): { baseURL: string; keyOrigin: string } {
  if (options.baseURL === undefined && options.keyOrigin === undefined) {
    throw new ConfigurationError("UnverifiedClient needs a baseURL or a keyOrigin; it never discovers a server by itself");
  }
  const keySource = options.keyOrigin ?? options.baseURL!;
  checkURL(keySource);
  const keyOrigin = originOf(keySource);
  const baseURL = options.baseURL ?? `${keyOrigin}/v1/`;
  checkURL(baseURL);
  return { baseURL: normalizeBaseURL(baseURL), keyOrigin };
}

/** HTTPS or loopback HTTP, as for a base URL, and no credentials, which the key fetch and the requests would otherwise send. */
function checkURL(url: string): void {
  validateBaseURL(url);
  const u = new URL(url);
  if (u.username !== "" || u.password !== "") throw new ConfigurationError(`URL must not carry credentials: ${JSON.stringify(url)}`);
}

/** @internal The factory with its test seams; {@link UnverifiedClient.create} is this without them. */
export async function createUnverifiedClient(options: UnverifiedOptions, seams: UnverifiedClientSeams): Promise<UnverifiedClient> {
  const { baseURL, keyOrigin } = checkUnverifiedOptions(options);
  (seams.warn ?? ((message: string) => console.warn(message)))(UNVERIFIED_WARNING);
  const send: Fetch = seams.fetch ?? ((input, init) => fetch(input, init));
  const identity = await fetchUnverifiedKey(keyOrigin, send, options.signal);
  const sealed = sealedFetchTo(identity, send);
  const baseOrigin = originOf(baseURL);
  const proxied = baseOrigin !== keyOrigin;
  const fetchImpl: Fetch = async (input, init) => {
    const url = input instanceof Request ? requestURL(input) : new URL(input instanceof URL ? input.href : input, baseURL);
    const origin = normalizedOrigin(url);
    if (origin !== baseOrigin) {
      throw new ConfigurationError(`refusing to send request to ${JSON.stringify(origin)}: client is bound to ${JSON.stringify(baseOrigin)}`);
    }
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    if (proxied) headers.set(ENCLAVE_URL_HEADER, keyOrigin);
    const target = input instanceof Request ? input : url;
    // The origin check covers the URL the request is sent to; a redirect
    // would carry the sealed body wherever it points, so none is followed.
    try {
      return await sealed.fetch(target, { ...init, headers, redirect: "error" });
    } catch (err) {
      // An aborted request surfaces its own reason, whichever signal carried it.
      const aborted = init?.signal?.aborted === true || (input instanceof Request && input.signal.aborted);
      if (err instanceof TinfoilError || aborted) throw err;
      throw new NetworkError(messageOf(err), { cause: err });
    }
  };
  return construct(baseURL, keyOrigin, fetchImpl);
}

/**
 * The server's key configuration from `keyOrigin`, taken on trust. The
 * request follows no redirect, and the configuration is bounded by its
 * declared length and again while it is read.
 */
async function fetchUnverifiedKey(keyOrigin: string, send: Fetch, signal: AbortSignal | undefined): Promise<Identity> {
  let response: Response;
  try {
    response = await send(`${keyOrigin}${PROTOCOL.KEYS_PATH}`, { method: "GET", redirect: "error", signal });
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
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > MAX_KEY_CONFIG_BYTES) {
    await response.body?.cancel().catch(() => {});
    throw new NetworkError(`fetching the server key: configuration exceeds ${MAX_KEY_CONFIG_BYTES} bytes`);
  }
  let bytes: Uint8Array;
  try {
    bytes = await readBounded(response, MAX_KEY_CONFIG_BYTES, "server key configuration");
  } catch (err) {
    if (signal?.aborted) throw err;
    throw new NetworkError(`fetching the server key: ${messageOf(err)}`, { cause: err });
  }
  try {
    return await Identity.unmarshalPublicConfig(bytes);
  } catch (err) {
    throw new NetworkError(`fetching the server key: ${messageOf(err)}`, { cause: err });
  }
}

/**
 * INSECURE: seals bodies to whatever key the server hands out, with no
 * attestation. For local development against a server without attestation
 * only; see the module header. Created only by {@link UnverifiedClient.create}:
 * the constructor is private, so type-checked code cannot call it, and a
 * call from untyped code is refused at runtime.
 */
export class UnverifiedClient {
  /**
   * Sends a request with its body sealed to the fetched key. A relative URL
   * is resolved against the base URL; a request to another origin is a
   * {@link ConfigurationError}.
   */
  readonly fetch: Fetch;
  /** Where requests go; always ends with `/`. */
  readonly baseURL: string;
  /** The origin the sealing key was fetched from. */
  readonly keyOrigin: string;

  private constructor(token: typeof TOKEN, baseURL: string, keyOrigin: string, fetchImpl: Fetch) {
    if (token !== TOKEN) throw new ConfigurationError("UnverifiedClient is created with UnverifiedClient.create");
    this.fetch = fetchImpl;
    this.baseURL = baseURL;
    this.keyOrigin = keyOrigin;
    Object.freeze(this);
  }

  static {
    construct = (...parts) => new UnverifiedClient(TOKEN, ...parts);
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
}
