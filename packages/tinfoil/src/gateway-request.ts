import { ConfigurationError } from "./errors.js";
import { bodyText, type PreparedRequest } from "./request.js";
import { topLevelValueRange, topLevelMembers, jsonValueEnd } from "./user-cache-secret.js";
const encoder = new TextEncoder();
const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const eligible = (pathname: string) => ["/chat/completions", "/completions", "/responses"].some(path => pathname.endsWith(path));

function compactJSON(raw: string): string {
  let inside = false, escaped = false, result = "";
  for (const char of raw) {
    if (inside || !/\s/.test(char)) result += char;
    if (escaped) escaped = false;
    else if (inside && char === "\\") escaped = true;
    else if (char === '"') inside = !inside;
  }
  return result;
}
function promptHead(raw: string, fields: Record<string, unknown>): string | undefined {
  for (const name of ["instructions", "messages", "input", "prompt"]) {
    const value = fields[name];
    if (name === "instructions" && (typeof value !== "string" || !value)) continue;
    if (value === undefined || value === null || (Array.isArray(value) && value.length === 0)) continue;
    const range = topLevelValueRange(raw, name);
    if (!range) continue;
    let valueRaw = raw.slice(...range);
    if (Array.isArray(value)) {
      const start = valueRaw.search(/\S/)+1;
      const offset = start + (valueRaw.slice(start).match(/^\s*/)?.[0].length ?? 0);
      const end = jsonValueEnd(valueRaw, offset);
      if (end === null) continue;
      valueRaw = valueRaw.slice(offset, end);
    }
    return compactJSON(valueRaw);
  }
  return undefined;
}
/** Rebuild members with original raw values, so int64 and decimal tokens survive. */
function cacheBody(raw: string, salt: string): string {
  const ranges = topLevelMembers(raw)!;
  let replaced = false;
  const members = ranges.filter(member => member.key !== "user_cache_secret").map(member => {
    if (member.key !== "cache_salt") return raw.slice(member.start, member.end);
    replaced = true;
    return raw.slice(member.start, member.valueStart) + JSON.stringify(salt) + raw.slice(member.valueEnd, member.end);
  });
  if (!replaced) members.push(`"cache_salt":${JSON.stringify(salt)}`);
  return raw.slice(0, raw.indexOf("{") + 1) + members.join(",") + raw.slice(raw.lastIndexOf("}"));
}
async function derive(secret: string, credential: string, domain: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: encoder.encode(credential), info: encoder.encode(domain) }, key, 256));
}
export async function shapeGatewayRequest(request: PreparedRequest, clientSecret: string): Promise<void> {
  const headers = new Headers(request.init.headers); request.init.headers = headers;
  if ((request.init.method ?? "GET").toUpperCase() !== "POST" || request.init.body == null) return;
  let contentType = headers.get("content-type") ?? "";
  if (request.init.body instanceof FormData && !contentType) {
    const normalized = new Request(request.url, request.init);
    contentType = normalized.headers.get("content-type")!;
    headers.set("content-type", contentType);
    request.init.body = normalized.body;
    request.replayable = false;
  }
  if (/^multipart\/form-data(?:;|$)/i.test(contentType)) {
    if (headers.has("X-Tinfoil-Model")) return;
    if (!/;\s*boundary=(?:"[^"]+"|[^;\s]+)/i.test(contentType)) throw new ConfigurationError("Multipart upload requires a boundary");
    const input = new Request(request.url, { ...request.init, duplex: "half" } as RequestInit);
    const reader = input.body!.getReader();
    const chunks: Uint8Array[] = []; let total = 0;
    try {
      for (;;) { const { done, value } = await reader.read(); if (done) break; total += value.length; if (total > 64 * 1024 * 1024) throw new ConfigurationError("Multipart upload exceeds 64 MiB"); chunks.push(value); }
    } finally { await reader.cancel(); reader.releaseLock(); }
    const body = new Uint8Array(total); let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
    let form: FormData;
    try { form = await new Response(body, { headers: { "content-type": contentType } }).formData(); }
    catch (cause) { throw new ConfigurationError("Malformed multipart upload", { cause }); }
    const models = form.getAll("model");
    if (models.length !== 1 || typeof models[0] !== "string" || !models[0].trim()) throw new ConfigurationError("Multipart upload requires exactly one nonempty model field, not a file");
    headers.set("X-Tinfoil-Model", models[0]); request.init.body = body; request.replayable = true;
    if (headers.has("content-length")) headers.set("content-length", String(body.length));
    return;
  }
  if (!/^application\/json(?:;|$)/i.test(contentType)) return;
  const raw = bodyText(request.init.body);
  if (raw === undefined) return;
  let fields: Record<string, unknown>;
  try { fields = JSON.parse(raw); } catch { return; }
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) return;
  if (!headers.has("X-Tinfoil-Model") && typeof fields.model === "string") headers.set("X-Tinfoil-Model", fields.model);
  if (!eligible(request.url.pathname)) return;
  const secret = typeof fields.user_cache_secret === "string" && fields.user_cache_secret ? fields.user_cache_secret : clientSecret;
  if (!secret) return;
  const credential = (headers.get("authorization")?.match(/^\s*Bearer\s+(.+?)\s*$/i)?.[1] ?? "").trim();
  const salt = await derive(secret, credential, "tinfoil/client-cache-salt/v2");
  const route = await derive(secret, credential, "tinfoil/client-cache-route/v2");
  const head = promptHead(raw, fields);
  headers.delete("X-Tinfoil-Cache-Prefix");
  if (head !== undefined) {
    const key = await crypto.subtle.importKey("raw", route as Uint8Array<ArrayBuffer>, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    headers.set("X-Tinfoil-Cache-Prefix", hex(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(head)))));
  }
  request.init.body = cacheBody(raw, b64url(salt));
  if (headers.has("content-length")) headers.set("content-length", String(encoder.encode(request.init.body).length));
}
export async function rankHosts(hosts: readonly string[], prefix: string, preferred?: string): Promise<string[]> {
  const ranked = [...hosts];
  if (!prefix) {
    const random = new Uint32Array(1);
    for (let i = ranked.length - 1; i > 0; i--) {
      const bound = i + 1;
      // Reject the partial range so each swap index has equally many outcomes.
      const limit = Math.floor(0x100000000 / bound) * bound;
      let sample: number;
      do { sample = crypto.getRandomValues(random)[0]; } while (sample >= limit);
      const j = sample % bound;
      [ranked[i], ranked[j]] = [ranked[j], ranked[i]];
    }
    return ranked;
  }
  const scores = new Map(await Promise.all(ranked.map(async host => {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${prefix}\0${host}`)));
    return [host, hex(digest.subarray(0, 8))] as const;
  })));
  ranked.sort((a, b) => scores.get(b)!.localeCompare(scores.get(a)!));
  if (preferred) { if (ranked.includes(preferred)) ranked.splice(ranked.indexOf(preferred), 1); ranked.unshift(preferred); }
  return ranked;
}
