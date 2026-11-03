import { int64, object, str } from "../../internal/json/decode.js";
import type { JsonObject, JsonValue } from "../../internal/json/index.js";

/** A VM shape. The counts are int64, kept exact as bigint. */
export interface Shape {
  readonly cpus: bigint;
  readonly memoryMb: bigint;
  readonly gpus?: bigint;
  readonly disks: bigint;
}

/** Informational build stack. */
export interface Stack {
  readonly qemu: string;
  readonly ovmf: string;
}

/** cpus, memory and disks equal; GPUs compared only when both are set. */
export function satisfies(s: Shape | undefined, required: Shape | undefined): boolean {
  if (s === undefined || required === undefined) return false;
  if (s.cpus !== required.cpus || s.memoryMb !== required.memoryMb || s.disks !== required.disks) return false;
  if (s.gpus !== undefined && required.gpus !== undefined && s.gpus !== required.gpus) return false;
  return true;
}

export const SHAPE_MEMBERS = ["cpus", "memory_mb", "gpus", "disks"] as const;

/** Decodes a Shape object; absent counts are 0. */
export function decodeShape(o: JsonObject): Shape {
  return {
    cpus: int64(o, "cpus") ?? 0n,
    memoryMb: int64(o, "memory_mb") ?? 0n,
    gpus: int64(o, "gpus"),
    disks: int64(o, "disks") ?? 0n,
  };
}

export function decodeStack(v: JsonValue, what: string): Stack {
  const o = object(v, what, ["qemu", "ovmf"]);
  return { qemu: str(o, "qemu"), ovmf: str(o, "ovmf") };
}

/** Renders a Shape for error messages. */
export function formatShape(s: Shape): string {
  const gpus = s.gpus === undefined ? "<nil>" : `0x${s.gpus.toString(16)}`;
  return `{CPUs:${s.cpus} MemoryMB:${s.memoryMb} GPUs:${gpus} Disks:${s.disks}}`;
}
