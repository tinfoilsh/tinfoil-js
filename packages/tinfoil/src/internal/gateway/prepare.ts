/**
 * What a request needs before the gateway can route it: the model it names,
 * in a header the gateway reads, taken from a JSON body's `model` field or a
 * multipart upload's `model` part when the caller didn't set the header; and
 * for the endpoints that prefix-cache, the cache scope. The scope is derived
 * client side, since no router sits between a gateway client and the
 * engine: the secret never leaves the client. The engine gets a salt
 * derived from it, and the gateway gets a cache-prefix key over the first
 * turn, which keeps a conversation on the same replica.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import { ConfigurationError } from "../../errors.js";
import { readAll } from "../body.js";
import { appendMember, firstArrayElement, objectMembers, pathEligible, removeMember, replaceMember, USER_CACHE_SECRET_FIELD, type Member } from "../cachesecret.js";
import type { RequestShape } from "../transport/transport.js";

export const MODEL_HEADER = "X-Tinfoil-Model";
export const CACHE_PREFIX_HEADER = "X-Tinfoil-Cache-Prefix";
export const CACHE_SALT_FIELD = "cache_salt";
/** The most of a JSON body or a multipart upload that is read to route it. */
export const MAX_BODY_BYTES = 64 << 20;
const CACHE_SALT_DOMAIN_TAG = "tinfoil/client-cache-salt/v2";
const CACHE_ROUTE_DOMAIN_TAG = "tinfoil/client-cache-route/v2";

/** A request's body as the gateway transport sends it: the caller's, or the bytes it read and may send again. */
export type PreparedBody = BodyInit | null | undefined;

export interface Prepared {
  readonly headers: Headers;
  readonly body: PreparedBody;
  /** Whether the body can be sent more than once. */
  readonly replayable: boolean;
}

/**
 * The headers and body to send: a JSON body with the model header set from
 * its `model` field and, on a prefix-caching endpoint, its cache scope
 * applied; a multipart upload with the model header set from its `model`
 * part. A request that already names its model and needs no cache scope
 * passes through unread, as does any other request. Reading a body makes
 * it replayable; a body over `limit` bytes is refused.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export async function prepare(shape: RequestShape, headers: Headers, body: PreparedBody, secret: string, limit = MAX_BODY_BYTES, signal?: AbortSignal): Promise<Prepared> {
  const passthrough: Prepared = { headers, body, replayable: !(body instanceof ReadableStream) };
  if (shape.method !== "POST" || body === undefined || body === null) return passthrough;
  const mediaType = mediaTypeOf(headers.get("content-type") ?? "");
  const explicitModel = headers.get(MODEL_HEADER) !== null;
  // A form body is multipart whatever the header says; fetch sets the header from it.
  if (body instanceof FormData || mediaType.type === "multipart/form-data") {
    // Explicit routing keeps uploads streaming.
    if (explicitModel) return passthrough;
    return prepareMultipart(headers, body, mediaType.params.get("boundary") ?? "", limit, signal);
  }
  if (mediaType.type !== "application/json") return passthrough;
  const scoped = pathEligible(shape);
  if (explicitModel && !scoped) return passthrough;
  const bytes = await readAll(body, limit, "JSON body", signal);
  let text: string | undefined;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { headers, body: bytes, replayable: true };
  }
  const members = objectMembers(text);
  if (members === null) return { headers, body: bytes, replayable: true };
  if (!explicitModel) {
    const models = members.filter((m) => m.key === "model");
    if (models.length > 1) throw new ConfigurationError("JSON body names a model more than once");
    const model = models[0];
    const value = model === undefined ? undefined : (JSON.parse(text.slice(model.valueStart, model.valueEnd)) as unknown);
    if (typeof value === "string" && value !== "") headers.set(MODEL_HEADER, value);
  }
  if (scoped) text = await scope(headers, text, members, secret);
  return { headers, body: text, replayable: true };
}

/**
 * Applies the cache scope to a JSON-object body: the per-request secret, or
 * else the client's, becomes a `cache_salt` member, replacing the secret
 * member and any `cache_salt` the caller wrote, and the prompt's first turn
 * becomes the cache-prefix header. With no secret, the body passes
 * unchanged. A body carrying either member more than once is refused, so
 * no copy of the secret can slip past the replacement.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export async function scopeCache(headers: Headers, text: string, clientSecret: string): Promise<string> {
  const members = objectMembers(text);
  if (members === null) return text;
  return scope(headers, text, members, clientSecret);
}

/** {@link scopeCache} over `members`, the body's members already parsed, so a body is scanned once. */
async function scope(headers: Headers, text: string, members: readonly Member[], clientSecret: string): Promise<string> {
  const secretMembers = members.filter((m) => m.key === USER_CACHE_SECRET_FIELD);
  if (secretMembers.length > 1) throw new ConfigurationError(`JSON body carries ${USER_CACHE_SECRET_FIELD} more than once`);
  if (members.filter((m) => m.key === CACHE_SALT_FIELD).length > 1) throw new ConfigurationError(`JSON body carries ${CACHE_SALT_FIELD} more than once`);
  const secretMember = secretMembers[0];
  let secret = "";
  if (secretMember !== undefined) {
    const value = JSON.parse(text.slice(secretMember.valueStart, secretMember.valueEnd)) as unknown;
    if (typeof value === "string") secret = value;
  }
  if (secret === "") secret = clientSecret;
  if (secret === "") return text;
  const apiKey = bearerCredential(headers.get("authorization") ?? "");
  const salt = await hkdf(secret, apiKey, CACHE_SALT_DOMAIN_TAG);
  headers.delete(CACHE_PREFIX_HEADER);
  const head = promptHead(text, members);
  if (head !== undefined) {
    const key = await hkdf(secret, apiKey, CACHE_ROUTE_DOMAIN_TAG);
    headers.set(CACHE_PREFIX_HEADER, await hmacHex(key, new TextEncoder().encode(head) as Uint8Array<ArrayBuffer>));
  }
  let out = text;
  let remaining = members;
  if (secretMember !== undefined) {
    out = removeMember(out, members, secretMember);
    remaining = objectMembers(out) ?? [];
  }
  const saltJSON = JSON.stringify(base64url(salt));
  const existing = remaining.find((m) => m.key === CACHE_SALT_FIELD);
  return existing === undefined ? appendMember(out, remaining, CACHE_SALT_FIELD, saltJSON) : replaceMember(out, existing, saltJSON);
}

/** The first element of a conversation, which later turns share: the instructions, or the first message, input or prompt item. */
function promptHead(text: string, members: readonly { key: string; valueStart: number; valueEnd: number }[]): string | undefined {
  const valueOf = (key: string): string | undefined => {
    const m = members.find((member) => member.key === key);
    return m === undefined ? undefined : text.slice(m.valueStart, m.valueEnd);
  };
  const instructions = valueOf("instructions");
  if (instructions !== undefined) {
    const value = JSON.parse(instructions) as unknown;
    if (typeof value === "string" && value !== "") return instructions;
  }
  for (const name of ["messages", "input", "prompt"]) {
    const raw = valueOf(name);
    if (raw === undefined || raw === "null") continue;
    const first = firstArrayElement(raw);
    if (first === undefined) return raw;
    if (first !== null) return first;
  }
  return undefined;
}

/**
 * The credential of a Bearer authorization, whose scheme is case-insensitive, and "" for any other scheme.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function bearerCredential(authorization: string): string {
  const trimmed = authorization.trim();
  const space = trimmed.indexOf(" ");
  if (space < 0) return "";
  if (trimmed.slice(0, space).toLowerCase() !== "bearer") return "";
  return trimmed.slice(space + 1).trim();
}

async function hkdf(secret: string, salt: string, info: string): Promise<Uint8Array<ArrayBuffer>> {
  const utf8 = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", utf8.encode(secret), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8.encode(salt), info: utf8.encode(info) }, key, 256));
}

async function hmacHex(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<string> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", k, data)), (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A multipart upload's model header from its `model` part, which must be exactly one non-empty field. */
async function prepareMultipart(headers: Headers, body: BodyInit, boundary: string, limit: number, signal?: AbortSignal): Promise<Prepared> {
  if (body instanceof FormData) {
    const values = body.getAll("model");
    if (values.length !== 1 || typeof values[0] !== "string" || values[0].trim() === "") {
      throw new ConfigurationError("multipart upload must contain exactly one non-empty model field");
    }
    headers.set(MODEL_HEADER, values[0]);
    return { headers, body, replayable: true };
  }
  if (boundary === "") throw new ConfigurationError("multipart upload is missing its boundary");
  const bytes = await readAll(body, limit, "multipart upload", signal);
  headers.set(MODEL_HEADER, multipartModel(bytes, boundary));
  return { headers, body: bytes, replayable: true };
}

const CR = 13;
const LF = 10;
const DASH = 45;

/**
 * The value of the one non-empty `model` field in a multipart body; a
 * {@link ConfigurationError} otherwise. Delimiters count only at the start
 * of the body or after a line break, so a boundary string inside a field's
 * value doesn't split it, and only the model field's bytes are decoded.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function multipartModel(bytes: Uint8Array, boundary: string): string {
  const delimiter = new TextEncoder().encode(`--${boundary}`);
  const models: string[] = [];
  let fileNamedModel = false;
  let at = nextDelimiter(bytes, delimiter, 0);
  if (at < 0) throw new ConfigurationError("invalid multipart upload: no boundary delimiter");
  for (;;) {
    const after = at + delimiter.length;
    if (bytes[after] === DASH && bytes[after + 1] === DASH) break;
    if (bytes[after] !== CR || bytes[after + 1] !== LF) throw new ConfigurationError("invalid multipart upload: malformed boundary delimiter");
    const partStart = after + 2;
    const next = nextDelimiter(bytes, delimiter, partStart);
    if (next < 0) throw new ConfigurationError("invalid multipart upload: unterminated part");
    // The line break before the next delimiter belongs to the delimiter, not the value.
    const partEnd = next - 2;
    const headersEnd = indexOf(bytes, [CR, LF, CR, LF], partStart, partEnd);
    if (headersEnd < 0) throw new ConfigurationError("invalid multipart upload: part without headers");
    const partHeaders = new TextDecoder("iso-8859-1").decode(bytes.subarray(partStart, headersEnd));
    const disposition = /^content-disposition:[ \t]*(.*)$/im.exec(partHeaders)?.[1] ?? "";
    const name = /;\s*name="([^"]*)"/i.exec(disposition)?.[1];
    if (name === "model") {
      if (/;\s*filename=/i.test(disposition)) fileNamedModel = true;
      else {
        try {
          models.push(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(headersEnd + 4, partEnd)));
        } catch {
          throw new ConfigurationError("invalid multipart upload: model field is not UTF-8");
        }
      }
    }
    at = next;
  }
  if (models.length !== 1 || models[0]!.trim() === "" || fileNamedModel) {
    throw new ConfigurationError("multipart upload must contain exactly one non-empty model field");
  }
  return models[0]!;
}

/** The index of the next delimiter at a valid position: the start of the body, or right after a CRLF. */
function nextDelimiter(bytes: Uint8Array, delimiter: Uint8Array, from: number): number {
  let index = from;
  for (;;) {
    index = indexOf(bytes, delimiter, index, bytes.length);
    if (index < 0) return -1;
    if (index === 0 || (index >= 2 && bytes[index - 2] === CR && bytes[index - 1] === LF)) return index;
    index += 1;
  }
}

/** The index of `needle` in `bytes` within [from, end), or -1. */
function indexOf(bytes: Uint8Array, needle: ArrayLike<number>, from: number, end: number): number {
  outer: for (let i = from; i + needle.length <= end; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/** A media type and its parameters, lower-cased, from a Content-Type value. */
function mediaTypeOf(contentType: string): { type: string; params: Map<string, string> } {
  const [type = "", ...rest] = contentType.split(";");
  const params = new Map<string, string>();
  for (const param of rest) {
    const eq = param.indexOf("=");
    if (eq < 0) continue;
    const name = param.slice(0, eq).trim().toLowerCase();
    let value = param.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    params.set(name, value);
  }
  return { type: type.trim().toLowerCase(), params };
}
