import { decodeBase64 } from "../../internal/canonical.js";
import { arr, object, str } from "../../internal/json/decode.js";
import { JsonError, type JsonValue } from "../../internal/json/index.js";
import { unmarshalData, type Entry } from "./collateral.js";

/** One captured Intel PCS response, replayed offline during quote verification. */
export interface PcsResponse {
  readonly url: string;
  /** Kept because Intel delivers issuer chains in response headers. Undefined for JSON null/absent. */
  readonly headers?: ReadonlyMap<string, readonly string[]>;
  readonly body: Uint8Array;
}

/** Captured Intel PCS responses. */
export interface IntelPcs {
  readonly responses: readonly PcsResponse[];
}

export function decodeIntelPcs(entry: Entry): IntelPcs {
  const wire = unmarshalData(entry, "intel-pcs", ["responses"], (o) =>
    (arr(o, "responses") ?? []).map((v) => {
      const r = object(v, "intel-pcs response", ["url", "headers", "body_base64"]);
      return { url: str(r, "url"), headers: headersOf(r.get("headers")), bodyBase64: str(r, "body_base64") };
    }),
  );
  const responses = wire.map((r, i): PcsResponse => {
    try {
      return { url: r.url, headers: r.headers, body: decodeBase64("body_base64", r.bodyBase64) };
    } catch (err) {
      throw new Error(`intel-pcs collateral entry "${entry.id}" response ${i}: ${(err as Error).message}`);
    }
  });
  return { responses };
}

/** Go map[string][]string: null/absent → undefined; each value a string array (null → empty). */
function headersOf(v: JsonValue | undefined): ReadonlyMap<string, readonly string[]> | undefined {
  if (v === undefined || v === null) return undefined;
  if (!(v instanceof Map)) throw new JsonError("headers must be an object");
  const out = new Map<string, readonly string[]>();
  for (const [name, values] of v) {
    if (values === null) {
      out.set(name, []);
      continue;
    }
    if (!Array.isArray(values)) throw new JsonError(`header ${name} must be an array`);
    out.set(
      name,
      values.map((s) => {
        if (s === null) return "";
        if (typeof s !== "string") throw new JsonError(`header ${name} values must be strings`);
        return s;
      }),
    );
  }
  return out;
}
