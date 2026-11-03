import { notImplemented } from "../../errors.js";

/** A VM shape. */
export interface Shape {
  readonly cpus: number;
  readonly memoryMb: number;
  readonly gpus?: number;
  readonly disks: number;
}

/** Informational build stack. */
export interface Stack {
  readonly qemu: string;
  readonly ovmf: string;
}

/** cpus, memory and disks equal; GPUs compared only when both are set. */
export function satisfies(s: Shape, required: Shape): boolean {
  return notImplemented("policy.satisfies");
}
