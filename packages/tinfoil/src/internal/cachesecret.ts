/**
 * The per-user prompt-cache secret: the router derives a request's
 * prefix-cache namespace from it, so requests carrying the same secret share
 * cached prompt prefixes and requests carrying different secrets cannot
 * observe each other's cache timing.
 *
 * Clients for Tinfoil's inference routes resolve it in this order; a client
 * for an explicit enclave uses only the first two, since other enclaves
 * don't read the field:
 *
 *  1. a non-empty `user_cache_secret` string in the request body,
 *  2. the client's `userCacheSecret` option,
 *  3. a random secret that is generated in memory once for the current
 *     runtime (the process, or the page in a browser) and shared by every
 *     client in it.
 *
 * The SDK reads no environment variable or file for it: an application that
 * wants a secret that is stable across processes or machines passes
 * `userCacheSecret` itself.
 *
 * The field is spliced into the body's text, so every other byte that the
 * caller wrote reaches the enclave unchanged. Injection happens below the
 * origin guard and above the sealing transport, so the secret is only ever
 * visible to the verified enclave.
 */
import type { Fetch } from "../options.js";
import { readAll } from "./body.js";
import { shapeOf, type RequestShape } from "./transport/transport.js";

/** The request-body field. A non-empty string scopes the prompt cache to that secret. */
export const USER_CACHE_SECRET_FIELD = "user_cache_secret";

/**
 * The endpoints whose bodies carry the field, matched by path suffix so a
 * path-prefixed proxy or a `/v1`-less root still qualifies. Other endpoints
 * (embeddings, audio, files) don't prefix-cache and may reject the field.
 */
const ELIGIBLE_PATHS = ["/chat/completions", "/completions", "/responses"];

/** Whether a request can carry the field: a POST with a body to one of the endpoints. */
export function pathEligible(request: RequestShape): boolean {
  return request.method === "POST" && request.hasBody && ELIGIBLE_PATHS.some((p) => request.url.pathname.endsWith(p));
}

/**
 * Resolves the client-level secret: a non-empty explicit option wins, then
 * the process's generated secret, on every runtime. Never throws; "" means
 * that no secret could be generated.
 */
export async function resolveUserCacheSecret(explicit: string | undefined): Promise<string> {
  if (explicit !== undefined && explicit !== "") return explicit;
  return processUserCacheSecret();
}

/** A fresh 256-bit random secret, hex-encoded; "" when no secure randomness is available. */
export function newUserCacheSecret(): string {
  try {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    console.warn("[tinfoil] could not generate a user cache secret; requests stay in the tenant-wide cache namespace");
    return "";
  }
}

/**
 * One secret for the life of the process (or page), generated on first use
 * and shared by every client in it. It isolates this process's cache
 * namespace; continuity resets when the process exits.
 */
let processSecret: string | undefined;
function processUserCacheSecret(): string {
  if (processSecret === undefined) processSecret = newUserCacheSecret();
  return processSecret;
}

/** Resets the process-lifetime secret; for tests. */
export function resetProcessUserCacheSecretForTests(): void {
  processSecret = undefined;
}

/**
 * `next` with `secret` added to the bodies of the requests that carry it. A
 * non-empty or non-string field already in the body is never overwritten; an
 * empty string is replaced. A body that is not UTF-8 text holding one JSON
 * object, or carries the field more than once, is forwarded untouched. An
 * empty secret returns `next`. An abort of the request's signal while its
 * body is being read stops the read and rejects with the signal's reason.
 */
export function withCacheSecret(next: Fetch, secret: string): Fetch {
  if (secret === "") return next;
  return async (input, init) => {
    if (!pathEligible(shapeOf(input, init))) return next(input, init);
    // A Request carries a signal of its own, which the init's replaces, as
    // fetch has it: an explicit null leaves the request without one.
    const signal = init?.signal === null ? undefined : (init?.signal ?? (input instanceof Request ? input.signal : undefined));
    const body = await readBody(input, init, signal);
    if (body === undefined) return next(input, init);
    const injected = body.text === undefined ? null : injectUserCacheSecret(body.text, secret);
    if (injected === null) {
      // A stream read here is forwarded as the bytes it carried.
      return body.consumed ? next(input, { ...init, body: body.bytes }) : next(input, init);
    }
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.delete("content-length");
    // The body keeps its kind, so the content type fetch infers from it
    // (text for a string, the blob's own type, none for bytes) is unchanged.
    return next(input, { ...init, body: body.rebuild(injected), headers });
  };
}

interface Body {
  readonly bytes: Uint8Array<ArrayBuffer>;
  /** The bytes as UTF-8 text; undefined when they are not valid UTF-8. */
  readonly text: string | undefined;
  /** Whether reading consumed the caller's body, so it must be forwarded as `bytes`. */
  readonly consumed: boolean;
  /** `text` as a body of the caller's kind. */
  readonly rebuild: (text: string) => BodyInit;
}

const asBytes = (text: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;

/**
 * The request body's bytes, read without consuming the caller's body where
 * the body can be read again. Undefined for a body kind that can't hold a
 * JSON text (form data, URL parameters), which is forwarded untouched. A
 * stream, the caller's or a Request's, is read until `signal` aborts.
 */
async function readBody(input: string | URL | Request, init: RequestInit | undefined, signal: AbortSignal | undefined): Promise<Body | undefined> {
  const source = init?.body;
  let bytes: Uint8Array<ArrayBuffer>;
  let consumed = false;
  let rebuild: Body["rebuild"] = asBytes;
  if (source === undefined || source === null) {
    if (!(input instanceof Request) || input.body === null) return undefined;
    bytes = await readAll(input.clone().body!, Infinity, "request body", signal);
  } else if (typeof source === "string") {
    return { bytes: asBytes(source), text: source, consumed: false, rebuild: (text) => text };
  } else if (source instanceof ArrayBuffer) {
    bytes = new Uint8Array(source.slice(0));
  } else if (ArrayBuffer.isView(source)) {
    bytes = new Uint8Array(source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength));
  } else if (typeof Blob !== "undefined" && source instanceof Blob) {
    bytes = new Uint8Array(await source.arrayBuffer());
    const type = source.type;
    rebuild = (text) => new Blob([text], { type });
  } else if (typeof ReadableStream !== "undefined" && source instanceof ReadableStream) {
    bytes = await readAll(source, Infinity, "request body", signal);
    consumed = true;
  } else {
    return undefined;
  }
  let text: string | undefined;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    text = undefined;
  }
  return { bytes, text, consumed, rebuild };
}

/**
 * Adds the field to a JSON-object body by splicing it into the text, so the
 * caller's bytes, including numbers beyond double precision, are preserved.
 * Returns null, meaning forward the original, for a body that is not one
 * JSON object with nothing but whitespace around it, carries the field more
 * than once, or carries it with a non-empty or non-string value. An existing
 * empty string is replaced.
 */
export function injectUserCacheSecret(raw: string, secret: string): string | null {
  const members = objectMembers(raw);
  if (members === null) return null;
  const existing = members.filter((m) => m.key === USER_CACHE_SECRET_FIELD);
  if (existing.length === 0) return appendMember(raw, members, USER_CACHE_SECRET_FIELD, JSON.stringify(secret));
  if (existing.length !== 1 || raw.slice(existing[0]!.valueStart, existing[0]!.valueEnd) !== '""') return null;
  return `${raw.slice(0, existing[0]!.valueStart)}${JSON.stringify(secret)}${raw.slice(existing[0]!.valueEnd)}`;
}

/** A member of a JSON object's text: its key and the range of its value and of the whole member. */
export interface Member {
  readonly key: string;
  readonly start: number;
  readonly valueStart: number;
  readonly valueEnd: number;
}

/**
 * The members of a JSON object's text, in order, with the ranges their
 * values occupy; null if the text is not one JSON object with nothing but
 * whitespace around it. The text is validated as JSON first, so the ranges
 * are those of well-formed values.
 */
export function objectMembers(raw: string): Member[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const members: Member[] = [];
  let index = skipWhitespace(raw, 0);
  if (raw[index] !== "{") return null;
  index = skipWhitespace(raw, index + 1);
  if (raw[index] === "}") return members;
  for (;;) {
    const start = index;
    const keyEnd = stringEnd(raw, index);
    if (keyEnd === null) return null;
    const key = JSON.parse(raw.slice(index, keyEnd)) as string;
    index = skipWhitespace(raw, keyEnd);
    if (raw[index] !== ":") return null;
    const valueStart = skipWhitespace(raw, index + 1);
    const valueEnd = valueEndAt(raw, valueStart);
    if (valueEnd === null) return null;
    members.push({ key, start, valueStart, valueEnd });
    index = skipWhitespace(raw, valueEnd);
    if (raw[index] === ",") {
      index = skipWhitespace(raw, index + 1);
      continue;
    }
    return raw[index] === "}" ? members : null;
  }
}

/** `raw` with `key: valueJSON` added as the last member. */
export function appendMember(raw: string, members: readonly Member[], key: string, valueJSON: string): string {
  const end = raw.lastIndexOf("}");
  return `${raw.slice(0, end)}${members.length > 0 ? "," : ""}${JSON.stringify(key)}:${valueJSON}${raw.slice(end)}`;
}

/** `raw` with `member`'s value replaced by `valueJSON`. */
export function replaceMember(raw: string, member: Member, valueJSON: string): string {
  return `${raw.slice(0, member.valueStart)}${valueJSON}${raw.slice(member.valueEnd)}`;
}

/** `raw` without `member`, and without the comma that separated it. */
export function removeMember(raw: string, members: readonly Member[], member: Member): string {
  const index = members.indexOf(member);
  const next = members[index + 1];
  if (next !== undefined) return raw.slice(0, member.start) + raw.slice(next.start);
  const previous = members[index - 1];
  if (previous !== undefined) return raw.slice(0, previous.valueEnd) + raw.slice(member.valueEnd);
  return raw.slice(0, member.start) + raw.slice(member.valueEnd);
}

/** The text of the first element of a JSON array's text; null for an empty array, undefined if the text is not an array. */
export function firstArrayElement(raw: string): string | null | undefined {
  let index = skipWhitespace(raw, 0);
  if (raw[index] !== "[") return undefined;
  index = skipWhitespace(raw, index + 1);
  if (raw[index] === "]") return null;
  const end = valueEndAt(raw, index);
  return end === null ? undefined : raw.slice(index, end);
}

function skipWhitespace(raw: string, start: number): number {
  let index = start;
  while (index < raw.length && (raw[index] === " " || raw[index] === "\t" || raw[index] === "\n" || raw[index] === "\r")) index++;
  return index;
}

function stringEnd(raw: string, start: number): number | null {
  if (raw[start] !== '"') return null;
  let escaped = false;
  for (let index = start + 1; index < raw.length; index++) {
    if (escaped) escaped = false;
    else if (raw[index] === "\\") escaped = true;
    else if (raw[index] === '"') return index + 1;
  }
  return null;
}

/** The end of the JSON value starting at `start`: a string, a nested structure, or a scalar running to the next ',', '}' or ']'. */
function valueEndAt(raw: string, start: number): number | null {
  if (raw[start] === '"') return stringEnd(raw, start);
  if (raw[start] === "{" || raw[start] === "[") {
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let index = start; index < raw.length; index++) {
      const c = raw[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (c === "\\") escaped = true;
        else if (c === '"') inString = false;
      } else if (c === '"') inString = true;
      else if (c === "{" || c === "[") depth++;
      else if (c === "}" || c === "]") {
        depth--;
        if (depth === 0) return index + 1;
      }
    }
    return null;
  }
  let end = start;
  while (end < raw.length && raw[end] !== "," && raw[end] !== "}" && raw[end] !== "]" && !/\s/.test(raw[end]!)) end++;
  return end > start ? end : null;
}
