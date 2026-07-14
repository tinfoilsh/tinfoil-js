import { isRealBrowser } from "./env.js";

/**
 * `user_cache_secret` provisions the per-user prompt-cache secret defined by
 * the secure prompt caching contract. The router derives the request's
 * prefix-cache namespace from it: requests carrying the same secret (under
 * the same API identity) share cached prompt prefixes, requests carrying
 * different secrets cannot observe each other's cache timing.
 *
 * Resolution order, mirroring the other Tinfoil clients:
 *
 *  1. a non-empty per-request `user_cache_secret` field in the body,
 *  2. the `userCacheSecret` client option,
 *  3. the TINFOIL_USER_CACHE_SECRET environment variable,
 *  4. an attempted generated secret persisted at
 *     ~/.tinfoil/user_cache_secret (0600), shared with other Tinfoil SDKs
 *     using the same home directory. Runtimes without a filesystem (browsers,
 *     edge runtimes) use a process-lifetime in-memory secret when secure
 *     random generation succeeds.
 *
 * Injection happens inside the secure transport — before the EHBP transport
 * encrypts the body, or on the way into the TLS connection pinned to the
 * attested key — so the secret is only ever visible to the verified enclave.
 */

/**
 * The router-only request-body field. A non-empty string scopes the prompt
 * cache to that secret.
 */
export const USER_CACHE_SECRET_FIELD = "user_cache_secret";

/**
 * Provisions the secret via the environment. An empty value is treated as
 * unset.
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
 * Resolves the client-level secret: a non-empty explicit option wins, then a
 * non-empty environment value, then an attempted persisted (or generated)
 * secret. Never throws.
 */
export async function resolveUserCacheSecret(explicit?: string): Promise<string> {
  if (explicit !== undefined && explicit !== "") {
    return explicit;
  }
  const env = typeof process !== "undefined" ? process.env?.[USER_CACHE_SECRET_ENV] : undefined;
  if (env !== undefined && env !== "") {
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
    console.warn(
      "[tinfoil] could not generate a user cache secret; automatic prompt-cache scoping is unavailable",
    );
    return "";
  }
}

/**
 * The process-lifetime fallback for when the secret cannot be persisted. When
 * secure random generation succeeds, an unpersisted secret still isolates
 * this process's cache namespace, but continuity is lost on restart — like a
 * session ID, it silently resets the namespace every deploy — so the fallback
 * warns once per process.
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
 * edge runtimes, an unwritable home directory) it uses a process-lifetime
 * in-memory secret when secure random generation succeeds.
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
 * already carries a non-empty or non-string field. An empty string is
 * replaced with the resolved client secret.
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
    const existing = (parsed as Record<string, unknown>)[USER_CACHE_SECRET_FIELD];
    if (existing !== "") {
      return null;
    }
    const range = topLevelValueRange(raw, USER_CACHE_SECRET_FIELD);
    if (range === null) {
      return null;
    }
    return raw.slice(0, range[0]) + JSON.stringify(secret) + raw.slice(range[1]);
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

function topLevelValueRange(raw: string, field: string): [number, number] | null {
  let index = skipWhitespace(raw, 0);
  let matchingRange: [number, number] | null = null;
  if (raw[index] !== "{") {
    return null;
  }
  index += 1;

  while (index < raw.length) {
    index = skipWhitespace(raw, index);
    if (raw[index] === "}") {
      return null;
    }
    const keyEnd = stringEnd(raw, index);
    if (keyEnd === null) {
      return null;
    }
    let key: unknown;
    try {
      key = JSON.parse(raw.slice(index, keyEnd));
    } catch {
      return null;
    }
    index = skipWhitespace(raw, keyEnd);
    if (raw[index] !== ":") {
      return null;
    }
    const valueStart = skipWhitespace(raw, index + 1);
    const valueEnd = jsonValueEnd(raw, valueStart);
    if (valueEnd === null) {
      return null;
    }
    if (key === field) {
      matchingRange = [valueStart, valueEnd];
    }
    index = skipWhitespace(raw, valueEnd);
    if (raw[index] === ",") {
      index += 1;
    } else if (raw[index] === "}") {
      return matchingRange;
    } else {
      return null;
    }
  }
  return null;
}

function skipWhitespace(raw: string, start: number): number {
  let index = start;
  while (index < raw.length && /\s/.test(raw[index])) {
    index += 1;
  }
  return index;
}

function stringEnd(raw: string, start: number): number | null {
  if (raw[start] !== "\"") {
    return null;
  }
  let escaped = false;
  for (let index = start + 1; index < raw.length; index += 1) {
    if (escaped) {
      escaped = false;
    } else if (raw[index] === "\\") {
      escaped = true;
    } else if (raw[index] === "\"") {
      return index + 1;
    }
  }
  return null;
}

function jsonValueEnd(raw: string, start: number): number | null {
  if (raw[start] === "\"") {
    return stringEnd(raw, start);
  }
  if (raw[start] === "{" || raw[start] === "[") {
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let index = start; index < raw.length; index += 1) {
      const character = raw[index];
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (character === "\\") {
          escaped = true;
        } else if (character === "\"") {
          inString = false;
        }
      } else if (character === "\"") {
        inString = true;
      } else if (character === "{" || character === "[") {
        depth += 1;
      } else if (character === "}" || character === "]") {
        depth -= 1;
        if (depth === 0) {
          return index + 1;
        }
      }
    }
    return null;
  }

  let end = start;
  while (end < raw.length && raw[end] !== "," && raw[end] !== "}") {
    end += 1;
  }
  while (end > start && /\s/.test(raw[end - 1])) {
    end -= 1;
  }
  return end > start ? end : null;
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
 * protected channel.
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
      ? {
          ...init,
          method: init.method ?? input.method,
          headers: init.headers ?? input.headers,
        }
      : init;
    let requestInit = normalized;
    if (
      input instanceof Request &&
      init?.body === undefined &&
      input.body !== null &&
      (init?.method ?? input.method).toUpperCase() === "POST" &&
      USER_CACHE_SECRET_PATHS.some((path) => pathname.endsWith(path))
    ) {
      try {
        requestInit = {
          ...init,
          method: init?.method ?? input.method,
          headers: init?.headers ?? input.headers,
          body: await input.clone().arrayBuffer(),
        };
      } catch {
        return inner(input, init);
      }
    }
    const injected = await injectUserCacheSecretIntoRequestInit(
      requestInit,
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
