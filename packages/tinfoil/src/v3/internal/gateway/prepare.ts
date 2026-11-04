/**
 * What a request needs before the gateway can route it: the model it names,
 * in a header the gateway reads, taken from a JSON body's `model` field or a
 * multipart upload's `model` part when the caller didn't set the header; and
 * for the endpoints that prefix-cache, the cache scope. The scope is derived
 * client side, since no router sits between a gateway client and the
 * engine: the secret never leaves the client. The engine gets a salt
 * derived from it, and the gateway gets a cache-prefix key over the first
 * turn, which keeps a conversation on the same replica.
 */
import { ConfigurationError } from "../../errors.js";
import { appendMember, firstArrayElement, objectMembers, pathEligible, removeMember, USER_CACHE_SECRET_FIELD } from "../cachesecret.js";
import type { RequestShape } from "../transport/transport.js";

export const MODEL_HEADER = "X-Tinfoil-Model";
export const CACHE_PREFIX_HEADER = "X-Tinfoil-Cache-Prefix";
export const CACHE_SALT_FIELD = "cache_salt";
export const MAX_MULTIPART_BODY_BYTES = 64 << 20;
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
 * part. Other requests pass through. Reading a body makes it replayable.
 */
export async function prepare(shape: RequestShape, headers: Headers, body: PreparedBody, secret: string): Promise<Prepared> {
  const replayable = !(body instanceof ReadableStream);
  if (shape.method !== "POST" || body === undefined || body === null) return { headers, body, replayable };
  const mediaType = mediaTypeOf(headers.get("content-type") ?? "");
  if (mediaType.type === "multipart/form-data") {
    // Explicit routing keeps uploads streaming.
    if (headers.get(MODEL_HEADER) !== null) return { headers, body, replayable };
    return prepareMultipart(headers, body, mediaType.params.get("boundary") ?? "");
  }
  if (mediaType.type !== "application/json") return { headers, body, replayable };
  const bytes = await readAll(body);
  let text: string | undefined;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { headers, body: bytes, replayable: true };
  }
  const members = objectMembers(text);
  if (members === null) return { headers, body: bytes, replayable: true };
  if (headers.get(MODEL_HEADER) === null) {
    const model = members.find((m) => m.key === "model");
    const value = model === undefined ? undefined : (JSON.parse(text.slice(model.valueStart, model.valueEnd)) as unknown);
    if (typeof value === "string" && value !== "") headers.set(MODEL_HEADER, value);
  }
  if (pathEligible(shape)) text = await scopeCache(headers, text, secret);
  return { headers, body: text, replayable: true };
}

/**
 * Applies the cache scope to a JSON-object body: the per-request secret, or
 * else the client's, becomes a `cache_salt` member, replacing the secret
 * member, and the prompt's first turn becomes the cache-prefix header. With
 * no secret, the body passes unchanged.
 */
export async function scopeCache(headers: Headers, text: string, clientSecret: string): Promise<string> {
  const members = objectMembers(text);
  if (members === null) return text;
  const secretMember = members.find((m) => m.key === USER_CACHE_SECRET_FIELD);
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
  return appendMember(out, remaining, CACHE_SALT_FIELD, JSON.stringify(base64url(salt)));
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

/** The credential of a Bearer authorization, whose scheme is case-insensitive, and "" for any other scheme. */
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
async function prepareMultipart(headers: Headers, body: BodyInit, boundary: string): Promise<Prepared> {
  if (body instanceof FormData) {
    const values = body.getAll("model");
    if (values.length !== 1 || typeof values[0] !== "string" || values[0].trim() === "") {
      throw new ConfigurationError("multipart upload must contain exactly one non-empty model field");
    }
    headers.set(MODEL_HEADER, values[0]);
    return { headers, body, replayable: true };
  }
  if (boundary === "") throw new ConfigurationError("multipart upload is missing its boundary");
  const bytes = await readAll(body, MAX_MULTIPART_BODY_BYTES);
  headers.set(MODEL_HEADER, multipartModel(bytes, boundary));
  return { headers, body: bytes, replayable: true };
}

/** The value of the one non-empty `model` field in a multipart body; a {@link ConfigurationError} otherwise. */
export function multipartModel(bytes: Uint8Array, boundary: string): string {
  // Field values are UTF-8; file parts are skipped by their disposition.
  const text = new TextDecoder("latin1").decode(bytes);
  const parts = text.split(`--${boundary}`);
  const models: string[] = [];
  let fileNamedModel = false;
  for (const part of parts.slice(1)) {
    if (part.startsWith("--")) break;
    const headersEnd = part.indexOf("\r\n\r\n");
    if (headersEnd < 0) throw new ConfigurationError("invalid multipart upload: part without headers");
    const partHeaders = part.slice(0, headersEnd);
    const disposition = /^content-disposition:\s*(.*)$/im.exec(partHeaders)?.[1] ?? "";
    const name = /;\s*name="([^"]*)"/i.exec(disposition)?.[1];
    if (name !== "model") continue;
    if (/;\s*filename=/i.test(disposition)) {
      fileNamedModel = true;
      continue;
    }
    let value = part.slice(headersEnd + 4);
    if (value.endsWith("\r\n")) value = value.slice(0, -2);
    models.push(new TextDecoder().decode(Uint8Array.from(value, (c) => c.charCodeAt(0))));
  }
  if (models.length !== 1 || models[0]!.trim() === "" || fileNamedModel) {
    throw new ConfigurationError("multipart upload must contain exactly one non-empty model field");
  }
  return models[0]!;
}

/** The body's bytes, within `limit`. */
async function readAll(body: BodyInit, limit = Number.POSITIVE_INFINITY): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof body === "string") return new TextEncoder().encode(body) as Uint8Array<ArrayBuffer>;
  const response = new Response(body);
  const reader = response.body?.getReader();
  if (reader === undefined) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new ConfigurationError(`reading multipart upload: body exceeds ${limit} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(new ArrayBuffer(total));
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
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
