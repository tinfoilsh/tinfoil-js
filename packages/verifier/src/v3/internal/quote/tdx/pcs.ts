/**
 * Intel PCS collateral replayed from captured responses: lookup by canonical
 * URL, TCB info and QE identity statements, and the certificate chains and
 * CRLs they reference.
 */
import type { PcsResponse } from "../../../document/collateral/tdx.js";
import { notImplemented } from "../../../errors.js";

/** The captured responses indexed by URL with the tcbEvaluationDataNumber query dropped, lowercased. */
export interface PcsCollateral {
  get(url: string): PcsResponse | undefined;
}

export function indexCollateral(responses: readonly PcsResponse[]): PcsCollateral {
  return notImplemented("tdx.indexCollateral");
}

export interface TcbInfo {
  readonly issueDate: Date;
  readonly nextUpdate: Date;
  readonly tcbEvaluationDataNumber: bigint;
  readonly fmspc: string;
  readonly tcbLevels: readonly TcbLevel[];
  readonly raw: Uint8Array;
}

export interface TcbLevel {
  readonly sgxComponents: readonly number[];
  readonly tdxComponents: readonly number[];
  readonly pceSvn: number;
  readonly status: string;
}

export interface QeIdentity {
  readonly issueDate: Date;
  readonly nextUpdate: Date;
  readonly tcbEvaluationDataNumber: bigint;
  readonly mrSigner: Uint8Array;
  readonly isvProdId: number;
  readonly attributes: Uint8Array;
  readonly attributesMask: Uint8Array;
  readonly miscSelect: Uint8Array;
  readonly miscSelectMask: Uint8Array;
  readonly tcbLevels: readonly { readonly isvSvn: number; readonly status: string }[];
  readonly raw: Uint8Array;
}

/** Parses and verifies a TCB info response: the signature by the TCB signing chain in the response headers. */
export async function tcbInfo(c: PcsCollateral, fmspc: string, now: Date): Promise<TcbInfo> {
  return notImplemented("tdx.tcbInfo");
}

export async function qeIdentity(c: PcsCollateral, now: Date): Promise<QeIdentity> {
  return notImplemented("tdx.qeIdentity");
}
