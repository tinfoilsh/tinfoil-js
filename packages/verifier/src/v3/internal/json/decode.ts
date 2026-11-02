/**
 * Helpers for hand-written struct decoders over strictParse output,
 * reproducing json v2 Unmarshal into a Go struct: member names match
 * case-sensitively, absent members take the zero value, a wrong JSON type is
 * an error, and `null` leaves the zero value.
 */
import { JsonError, JsonNumber, type JsonObject, type JsonValue } from "./index.js";

const EMPTY: JsonObject = new Map();

/**
 * Requires `v` to be an object. With `known` set, members outside it reject
 * (json.RejectUnknownMembers(true)). As in Go, `null` decodes to the zero
 * struct, i.e. an empty object; callers modelling a Go *T must check for
 * null themselves.
 */
export function object(v: JsonValue, what: string, known?: readonly string[]): JsonObject {
  if (v === null) return EMPTY;
  if (!(v instanceof Map)) {
    throw new JsonError(`cannot unmarshal JSON ${kind(v)} into ${what}`);
  }
  if (known !== undefined) {
    for (const name of v.keys()) {
      if (known.indexOf(name) < 0) {
        throw new JsonError(`cannot unmarshal into ${what}: unknown object member name ${JSON.stringify(name)}`);
      }
    }
  }
  return v;
}

/** A string member; absent or null is "". */
export function str(o: JsonObject, key: string): string {
  const v = o.get(key);
  if (v === undefined || v === null) return "";
  if (typeof v !== "string") throw typeError(v, "string", key);
  return v;
}

/** A boolean member; absent or null is false. */
export function bool(o: JsonObject, key: string): boolean {
  const v = o.get(key);
  if (v === undefined || v === null) return false;
  if (typeof v !== "boolean") throw typeError(v, "bool", key);
  return v;
}

/** A number member, or undefined when absent or null (Go *T fields). */
export function num(o: JsonObject, key: string): JsonNumber | undefined {
  const v = o.get(key);
  if (v === undefined || v === null) return undefined;
  if (!(v instanceof JsonNumber)) throw typeError(v, "number", key);
  return v;
}

/** An array member; absent or null is undefined (Go nil slice). */
export function arr(o: JsonObject, key: string): readonly JsonValue[] | undefined {
  const v = o.get(key);
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v)) throw typeError(v, "slice", key);
  return v as readonly JsonValue[];
}

/** A raw member kept undecoded (Go jsontext.Value); absent is undefined, null is null. */
export function raw(o: JsonObject, key: string): JsonValue | undefined {
  return o.get(key);
}

function kind(v: JsonValue): string {
  if (v === null) return "null";
  if (typeof v === "string") return "string";
  if (typeof v === "boolean") return "boolean";
  if (v instanceof JsonNumber) return "number";
  if (Array.isArray(v)) return "array";
  return "object";
}

function typeError(v: JsonValue, goType: string, key: string): JsonError {
  return new JsonError(`cannot unmarshal JSON ${kind(v)} into Go ${goType} within ${JSON.stringify("/" + key)}`);
}
