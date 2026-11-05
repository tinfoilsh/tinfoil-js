export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const text = (b: Uint8Array): string =>
  new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b);
export const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function unhex(s: unknown, size?: number, lowercase = true): Uint8Array {
  if (
    typeof s !== "string" ||
    !s.length ||
    s.length % 2 ||
    !(lowercase ? /^[0-9a-f]+$/ : /^[0-9a-fA-F]+$/).test(s) ||
    (size !== undefined && s.length !== size * 2)
  )
    throw new Error(
      `Invalid ${size === undefined ? "" : size + "-byte "}hex value`,
    );
  return Uint8Array.from(s.match(/../g)!, (x) => Number.parseInt(x, 16));
}
export function base64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 8192)
    s += String.fromCharCode(...b.subarray(i, i + 8192));
  return btoa(s);
}
export function unbase64(s: unknown): Uint8Array {
  if (
    typeof s !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)
  )
    throw new Error("Noncanonical base64");
  const b = Uint8Array.from(atob(s), (x) => x.charCodeAt(0));
  if (base64(b) !== s) throw new Error("Noncanonical base64 padding");
  return b;
}
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let n = 0;
  for (const a of arrays) {
    out.set(a, n);
    n += a.length;
  }
  return out;
}
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
export async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", b as BufferSource),
  );
}
export function object(v: unknown, label = "value"): Record<string, any> {
  if (!v || typeof v !== "object" || Array.isArray(v))
    throw new Error(`${label} must be an object`);
  return v as Record<string, any>;
}
export function fields(
  v: unknown,
  allowed: readonly string[],
  required: readonly string[] = allowed,
): Record<string, any> {
  const o = object(v);
  for (const k of Object.keys(o))
    if (!allowed.includes(k)) throw new Error(`Unknown member ${k}`);
  for (const k of required)
    if (!(k in o)) throw new Error(`Missing member ${k}`);
  return o;
}
export function string(v: unknown, label = "value"): string {
  if (typeof v !== "string") throw new Error(`${label} must be a string`);
  return v;
}
export function array(v: unknown, label = "value"): any[] {
  if (!Array.isArray(v)) throw new Error(`${label} must be an array`);
  return v;
}
export function nonempty(v: unknown, label = "value"): string {
  const s = string(v, label);
  if (!s) throw new Error(`${label} must not be empty`);
  return s;
}
/** JSON parsing with UTF-8, duplicate-member, unpaired-surrogate and trailing-data rejection. */
export function parseJSON(bytes: Uint8Array | string): any {
  const source = typeof bytes === "string" ? bytes : text(bytes);
  let i = 0;
  const ws = () => {
    while (/[\x20\t\r\n]/.test(source[i] ?? "x")) i++;
  };
  const str = (): string => {
    const start = i++;
    while (i < source.length) {
      const c = source[i++];
      if (c === '"') {
        const s = JSON.parse(source.slice(start, i));
        for (let n = 0; n < s.length; n++) {
          const u = s.charCodeAt(n);
          if (u >= 0xd800 && u <= 0xdbff) {
            const v = s.charCodeAt(++n);
            if (!(v >= 0xdc00 && v <= 0xdfff))
              throw new Error("Unpaired JSON surrogate");
          } else if (u >= 0xdc00 && u <= 0xdfff)
            throw new Error("Unpaired JSON surrogate");
        }
        return s;
      }
      if (c === "\\") i++;
    }
    throw new Error("Unterminated JSON string");
  };
  const value = (depth: number): any => {
    if (depth > 128) throw new Error("JSON nesting exceeds limit");
    ws();
    const c = source[i];
    if (c === '"') return str();
    if (c === "{") {
      i++;
      ws();
      const out: Record<string, any> = Object.create(null),
        seen = new Set<string>();
      if (source[i] === "}") {
        i++;
        return out;
      }
      while (true) {
        ws();
        if (source[i] !== '"') throw new Error("Expected JSON member");
        const k = str();
        if (seen.has(k)) throw new Error(`Duplicate JSON member ${k}`);
        seen.add(k);
        ws();
        if (source[i++] !== ":") throw new Error("Expected JSON colon");
        out[k] = value(depth + 1);
        ws();
        const end = source[i++];
        if (end === "}") return out;
        if (end !== ",") throw new Error("Expected JSON comma");
      }
    }
    if (c === "[") {
      i++;
      ws();
      const out: any[] = [];
      if (source[i] === "]") {
        i++;
        return out;
      }
      while (true) {
        out.push(value(depth + 1));
        ws();
        const end = source[i++];
        if (end === "]") return out;
        if (end !== ",") throw new Error("Expected JSON comma");
      }
    }
    const m =
      /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(
        source.slice(i),
      );
    if (!m) throw new Error("Invalid JSON value");
    i += m[0].length;
    const v =
      /^-?[0-9]+$/.test(m[0]) && !Number.isSafeInteger(Number(m[0]))
        ? BigInt(m[0])
        : JSON.parse(m[0]);
    if (typeof v === "number" && !Number.isFinite(v))
      throw new Error("Nonfinite JSON number");
    return v;
  };
  const out = value(0);
  ws();
  if (i !== source.length) throw new Error("Trailing JSON data");
  return out;
}
export function canonicalJSON(value: any): string {
  if (typeof value === "bigint") return value.toString();
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonicalJSON).join(",") + "]";
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalJSON(value[k]))
      .join(",") +
    "}"
  );
}
