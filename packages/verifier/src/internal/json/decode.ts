/**
 * Helpers for hand-written record decoders over strictParse output. Member
 * names match case-sensitively; a missing member decodes to its type's
 * empty value (empty string, false, an empty object or map) or, for the
 * number and array helpers, to `undefined`; `null` decodes the same way; a
 * member of the wrong JSON type is an error.
 */
import { JsonError, JsonNumber, type JsonObject, type JsonValue } from "./index.js";

/**
 * Requires `v` to be an object. With `known` set, members outside it reject.
 * `null` decodes to an empty object; callers that need to tell null from an
 * object must check before calling.
 */
export function object(v: JsonValue, what: string, known?: readonly string[]): JsonObject {
  if (v === null) return new Map();
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

/** A number member, or undefined when absent or null. */
export function num(o: JsonObject, key: string): JsonNumber | undefined {
  const v = o.get(key);
  if (v === undefined || v === null) return undefined;
  if (!(v instanceof JsonNumber)) throw typeError(v, "number", key);
  return v;
}

/** An array member; absent or null is undefined. */
export function arr(o: JsonObject, key: string): readonly JsonValue[] | undefined {
  const v = o.get(key);
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v)) throw typeError(v, "slice", key);
  return v as readonly JsonValue[];
}

/**
 * A nested record member whose absence means "all fields zero": absent or
 * null is an empty object; otherwise an object with exactly `known` members.
 */
export function struct(o: JsonObject, key: string, known: readonly string[]): JsonObject {
  const v = o.get(key);
  if (v === undefined || v === null) return new Map();
  return object(v, key, known);
}

/** A member kept as parsed JSON; absent is undefined, null is null. */
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

function typeError(v: JsonValue, wantType: string, key: string): JsonError {
  return new JsonError(`cannot unmarshal JSON ${kind(v)} into ${wantType} within ${JSON.stringify("/" + key)}`);
}

/**
 * An unsigned integer member of `bits` width, or undefined when absent or
 * null. Any leading '-' rejects, so "-0" rejects; so does a fraction, an
 * exponent or an out-of-range value.
 */
export function uint(o: JsonObject, key: string, bits: 8 | 32 | 64): bigint | undefined {
  const n = num(o, key);
  if (n === undefined) return undefined;
  if (n.raw.startsWith("-")) throw new JsonError(`cannot unmarshal JSON number ${n.raw} into uint${bits} within ${JSON.stringify("/" + key)}`);
  const v = n.toBigInt();
  if (v >= 1n << BigInt(bits)) throw new JsonError(`JSON number ${n.raw} overflows uint${bits} within ${JSON.stringify("/" + key)}`);
  return v;
}

/** A signed 64-bit integer member, or undefined when absent or null. */
export function int64(o: JsonObject, key: string): bigint | undefined {
  const n = num(o, key);
  if (n === undefined) return undefined;
  const v = n.toBigInt();
  if (v >= 1n << 63n || v < -(1n << 63n)) throw new JsonError(`JSON number ${n.raw} overflows int64 within ${JSON.stringify("/" + key)}`);
  return v;
}

/** An optional nested record member: absent or null is undefined; otherwise an object with exactly `known` members. */
export function optStruct(o: JsonObject, key: string, known: readonly string[]): JsonObject | undefined {
  const v = o.get(key);
  if (v === undefined || v === null) return undefined;
  return object(v, key, known);
}

/** A string-keyed map member: absent or null is an empty map; values decoded by `value`. */
export function map<T>(o: JsonObject, key: string, value: (v: JsonValue, name: string) => T): Map<string, T> {
  const v = o.get(key);
  const out = new Map<string, T>();
  if (v === undefined || v === null) return out;
  if (!(v instanceof Map)) throw typeError(v, "map", key);
  for (const [name, item] of v) out.set(name, value(item, name));
  return out;
}

/** A string-array member: absent or null is undefined; null elements are "". */
export function strArr(o: JsonObject, key: string): string[] | undefined {
  const a = arr(o, key);
  return a?.map((s) => {
    if (s === null) return "";
    if (typeof s !== "string") throw new JsonError(`cannot unmarshal JSON ${kind(s)} into string within ${JSON.stringify("/" + key)}`);
    return s;
  });
}
