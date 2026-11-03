import { int64, object, str, strArr } from "../../internal/json/decode.js";
import type { JsonValue } from "../../internal/json/index.js";
import { decodeHex } from "./artifact.js";

/** The TDX policy block. Hex fields are lowercase. */
export interface TdxPolicy {
  readonly qeVendorId: string;
  readonly minimumTeeTcbSvn: string;
  readonly mrSeam: string;
  readonly tdAttributes: string;
  readonly xfam: string;
  /** int64. */
  readonly minimumTcbEvaluationDataNumber?: bigint;
  /** v1 only: names of acceptable platform measurements. Undefined when absent. */
  readonly platformMeasurements?: readonly string[];
}

const MEMBERS = [
  "qe_vendor_id",
  "minimum_tee_tcb_svn",
  "mr_seam",
  "td_attributes",
  "xfam",
  "minimum_tcb_evaluation_data_number",
  "platform_measurements",
] as const;

/** Strict decode of the tdx block. */
export function decodeTdxPolicy(v: JsonValue, what: string): TdxPolicy {
  const o = object(v, what, MEMBERS);
  return {
    qeVendorId: str(o, "qe_vendor_id"),
    minimumTeeTcbSvn: str(o, "minimum_tee_tcb_svn"),
    mrSeam: str(o, "mr_seam"),
    tdAttributes: str(o, "td_attributes"),
    xfam: str(o, "xfam"),
    minimumTcbEvaluationDataNumber: int64(o, "minimum_tcb_evaluation_data_number"),
    platformMeasurements: strArr(o, "platform_measurements"),
  };
}

/** Required fields; evaluation number ≥ 0; hex lengths 16/16/48/8/8. */
export function validateTdxPolicy(p: TdxPolicy): void {
  if (p.qeVendorId === "") throw new Error("qe_vendor_id is required");
  if (p.minimumTeeTcbSvn === "") throw new Error("minimum_tee_tcb_svn is required");
  if (p.mrSeam === "") throw new Error("mr_seam is required");
  if (p.tdAttributes === "") throw new Error("td_attributes is required");
  if (p.xfam === "") throw new Error("xfam is required");
  if (p.minimumTcbEvaluationDataNumber === undefined) throw new Error("minimum_tcb_evaluation_data_number is required");
  if (p.minimumTcbEvaluationDataNumber < 0n) throw new Error("minimum_tcb_evaluation_data_number must not be negative");
  validatePolicyHex("qe_vendor_id", p.qeVendorId, 16);
  validatePolicyHex("minimum_tee_tcb_svn", p.minimumTeeTcbSvn, 16);
  validatePolicyHex("mr_seam", p.mrSeam, 48);
  validatePolicyHex("td_attributes", p.tdAttributes, 8);
  validatePolicyHex("xfam", p.xfam, 8);
}

/** Exact length, lowercase, and decodable hex. */
export function validatePolicyHex(name: string, value: string, byteLen: number): void {
  if (value.length !== 2 * byteLen) throw new Error(`${name} must be ${2 * byteLen} hex chars, got ${value.length}`);
  if (value !== value.toLowerCase()) throw new Error(`${name} must be lowercase hex`);
  decodeHex(name, value, byteLen);
}
