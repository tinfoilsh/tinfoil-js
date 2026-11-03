import { notImplemented } from "../../errors.js";

/** The TDX policy block. Hex fields are lowercase. */
export interface TdxPolicy {
  readonly qeVendorId: string;
  readonly minimumTeeTcbSvn: string;
  readonly mrSeam: string;
  readonly tdAttributes: string;
  readonly xfam: string;
  readonly minimumTcbEvaluationDataNumber?: number;
  /** v1 only: names of acceptable platform measurements. */
  readonly platformMeasurements?: readonly string[];
}

/** Strict decode of the tdx block. */
export function decodeTdxPolicy(v: unknown): TdxPolicy {
  return notImplemented("policy.decodeTdxPolicy");
}

/** Required fields; evaluation number ≥ 0; hex lengths 16/16/48/8/8. */
export function validateTdxPolicy(p: TdxPolicy): void {
  return notImplemented("policy.validateTdxPolicy");
}
