import { isRealBrowser } from "./env.js";

/**
 * `user_cache_secret` provisions the per-user prompt-cache secret defined by
 * the secure prompt caching contract. The router derives the request's
 * prefix-cache namespace from it: requests carrying the same secret (under
 * the same API identity) share cached prompt prefixes, requests carrying
 * different secrets cannot observe each other's cache timing. The secret
 * itself is stripped by the router and never reaches the model.
 *
 * Resolution order, mirroring the other Tinfoil clients:
 *
 *  1. an explicit per-request `user_cache_secret` field in the body (never
 *     overwritten here),
 *  2. the `userCacheSecret` client option,
 *  3. the TINFOIL_USER_CACHE_SECRET environment variable,
 *  4. a generated secret persisted at ~/.tinfoil/user_cache_secret (0600),
 *     shared with the other Tinfoil SDKs on the same machine. Runtimes
 *     without a filesystem (browsers, edge runtimes) fall back to a
 *     process-lifetime in-memory secret.
 *
 * Injection happens inside the secure transport — before the EHBP transport
 * encrypts the body, or on the way into the TLS connection pinned to the
 * attested key — so the secret is only ever visible to the verified enclave.
 */

/**
 * The router-only request-body field. A non-empty string scopes the prompt
 * cache to that secret; an absent or empty value leaves the request in the
 * tenant-wide namespace.
 */
export const USER_CACHE_SECRET_FIELD = "user_cache_secret";

/**
 * Provisions the secret via the environment. Setting it to an empty string
 * disables generation entirely (tenant-wide caching), which is the right
 * call for pooled multi-user deployments that would otherwise mint a fresh
 * namespace per container.
 */
export const USER_CACHE_SECRET_ENV = "TINFOIL_USER_CACHE_SECRET";

/**
 * The OpenAI-compatible endpoints whose bodies carry the field. Matched by
 * path suffix with no /v1 prefix required, so custom base URLs
 * (path-prefixed proxies or /v1-less roots) still qualify. Other endpoints
 * (embeddings, audio, files) are excluded: their engines do not prefix-cache
 * and may reject unknown fields.
 */
const USER_CACHE_SECRET_PATHS = [
  "/chat/completions",
  "/completions",
  "/responses",
];

/**
 * Resolves the client-level secret: the explicit option wins (an explicit
 * empty string disables provisioning), then the environment, then the
 * persisted (or generated) secret. An empty result means injection is
 * disabled. Never throws.
 */
export async function resolveUserCacheSecret(explicit?: string): Promise<string> {
  if (explicit !== undefined) {
    return explicit;
  }
  // A set-but-empty variable counts as set: it disables generation, which is
  // what pooled multi-user deployments want. Browser bundles have no process.
  const env = typeof process !== "undefined" ? process.env?.[USER_CACHE_SECRET_ENV] : undefined;
  if (env !== undefined) {
    return env;
  }
  return loadOrGenerateUserCacheSecret();
}

/** Returns a fresh 256-bit random secret, hex-encoded. */
function newUserCacheSecret(): string {
  try {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    // Never fall back to a weak secret: no secret means tenant-wide caching,
    // which is safe.
    console.warn(
      "[tinfoil] could not generate a user cache secret; requests stay in the tenant-wide cache namespace",
    );
    return "";
  }
}

/**
 * The process-lifetime fallback for when the secret cannot be persisted. An
 * unpersisted secret still isolates this process's cache namespace, but
 * continuity is lost on restart — like a session ID, it silently resets the
 * namespace every deploy — so the fallback warns once per process.
 */
let ephemeralUserCacheSecret: string | undefined;

function getEphemeralUserCacheSecret(): string {
  if (ephemeralUserCacheSecret === undefined) {
    ephemeralUserCacheSecret = newUserCacheSecret();
    if (ephemeralUserCacheSecret !== "") {
      console.warn(
        "[tinfoil] could not persist the user cache secret; using an in-memory secret, " +
          "so prompt-cache continuity resets when this process exits " +
          `(set ${USER_CACHE_SECRET_ENV} or the userCacheSecret option to pin one)`,
      );
    }
  }
  return ephemeralUserCacheSecret;
}

/**
 * Returns the secret persisted under the user's home directory, generating
 * and persisting one on first use. Without a usable filesystem (browsers,
 * edge runtimes, an unwritable home directory) it falls back to the
 * process-lifetime in-memory secret.
 */
async function loadOrGenerateUserCacheSecret(): Promise<string> {
  if (!isRealBrowser()) {
    try {
      // Dynamic import to keep Node.js fs/os modules out of browser bundles;
      // package.json's browser field maps the store to a stub, the same way
      // pinned-tls-fetch is gated.
      const { loadOrPersistUserCacheSecret } = await import("./user-cache-secret-store.js");
      const secret = loadOrPersistUserCacheSecret(newUserCacheSecret);
      if (secret !== null) {
        return secret;
      }
    } catch {
      // No usable filesystem in this runtime: fall through.
    }
  }
  return getEphemeralUserCacheSecret();
}

/**
 * Adds the field to a JSON-object body. Returns null — forward the original
 * body untouched — for non-object bodies, trailing data, or a body that
 * already carries the field (an explicit per-request value, including an
 * explicit empty string, always wins).
 */
export function injectUserCacheSecret(raw: string, secret: string): string | null {
  let parsed: unknown;
  try {
    // JSON.parse enforces exactly the framing we need: a single
    // value followed by nothing but whitespace. Trailing data ('{...}}',
    // '{...} garbage') throws, so a body the server would reject is forwarded
    // as-is instead of being quietly rewritten into one it accepts.
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  if (Object.prototype.hasOwnProperty.call(parsed, USER_CACHE_SECRET_FIELD)) {
    return null;
  }
  // Splice the field into the original text instead of re-serializing the
  // parsed object: parsing round-trips numbers through float64, which would
  // corrupt int64-range values such as `"seed": 9007199254740993`. The last
  // '}' is the object's closing brace — only whitespace may follow it.
  const end = raw.lastIndexOf("}");
  const field = `${JSON.stringify(USER_CACHE_SECRET_FIELD)}:${JSON.stringify(secret)}`;
  const separator = Object.keys(parsed).length > 0 ? "," : "";
  return raw.slice(0, end) + separator + field + raw.slice(end);
}

/**
 * Decodes supported replayable in-memory bodies. Other representations are
 * forwarded unchanged, so callers using them must provide the field.
 */
function bodyText(body: BodyInit | null | undefined): string | null {
  if (typeof body === "string") {
    return body;
  }
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(body);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Rewrites a caller-supplied Content-Length header to describe the injected
 * body. Fetch implementations compute the length themselves when the header
 * is absent, so it is only touched when the caller set one.
 */
function headersWithUpdatedBodyMetadata(
  headers: HeadersInit | undefined,
  body: string,
): HeadersInit | undefined {
  if (headers === undefined) {
    return headers;
  }
  const updated = new Headers(headers);
  if (updated.has("content-length")) {
    updated.set("content-length", String(new TextEncoder().encode(body).byteLength));
    return updated;
  }
  return headers;
}

/**
 * Injects the client-level secret into an eligible request: a POST with a
 * JSON-object body to one of the supported endpoints. Anything else — other
 * endpoints, non-object bodies, or a body that already carries the field —
 * passes through untouched. Never throws. The caller
 * runs this inside the sealing boundary, so retries and redirects below the
 * transport replay the injected body, not the caller's original.
 */
export async function injectUserCacheSecretIntoRequestInit(
  init: RequestInit | undefined,
  pathname: string,
  secret: string,
): Promise<RequestInit | undefined> {
  if (secret === "" || init === undefined) {
    return init;
  }
  if ((init.method ?? "GET").toUpperCase() !== "POST") {
    return init;
  }
  if (!USER_CACHE_SECRET_PATHS.some((path) => pathname.endsWith(path))) {
    return init;
  }
  const raw = bodyText(init.body);
  if (raw === null || raw === "") {
    return init;
  }
  const injected = injectUserCacheSecret(raw, secret);
  if (injected === null) {
    return init;
  }
  return {
    ...init,
    body: injected,
    headers: headersWithUpdatedBodyMetadata(init.headers, injected),
  };
}

/**
 * Wraps a fetch function so eligible request bodies carry the secret. The
 * wrapper sits directly above the sealing fetch (the TLS connection pinned
 * to the attested key), so the injected field never travels outside the
 * protected channel. An empty secret disables injection entirely.
 */
export function withUserCacheSecret(
  inner: typeof fetch,
  baseURL: string,
  secret: string,
): typeof fetch {
  if (secret === "") {
    return inner;
  }
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    let pathname: string;
    try {
      pathname = requestPathname(input, baseURL);
    } catch {
      // An unresolvable URL is the inner fetch's error to raise.
      return inner(input, init);
    }
    const normalized = input instanceof Request && init?.body !== undefined
      ? { method: input.method, headers: input.headers, ...init }
      : init;
    const injected = await injectUserCacheSecretIntoRequestInit(
      normalized,
      pathname,
      secret,
    );
    return inner(input, injected);
  }) as typeof fetch;
}

/** Resolves the request path the same way the pinned TLS fetch does. */
function requestPathname(input: RequestInfo | URL, baseURL: string): string {
  if (typeof input === "string") {
    return new URL(input, baseURL).pathname;
  }
  if (input instanceof URL) {
    return input.pathname;
  }
  return new URL((input as Request).url, baseURL).pathname;
}
