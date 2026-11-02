/** Size in bytes of every measurement register (SNP launch, TDX MRTD/RTMRs). */
export const REGISTER_SIZE = 48;

/** A 48-byte measurement register. */
export type Register = Uint8Array;

/** An AMD SEV-SNP launch measurement. */
export interface SevSnpMeasurement {
  readonly platform: "sev-snp";
  readonly launch: Register;
}

/** An Intel TDX build-time measurement and its four runtime registers. */
export interface TdxMeasurement {
  readonly platform: "tdx";
  readonly mrtd: Register;
  readonly rtmr0: Register;
  readonly rtmr1: Register;
  readonly rtmr2: Register;
  readonly rtmr3: Register;
}

/** The registers a CPU measured at launch. */
export type Measurement = SevSnpMeasurement | TdxMeasurement;

/** Constrains an SEV-SNP launch measurement; `undefined` is unconstrained. */
export interface ExpectedSevSnp {
  readonly platform: "sev-snp";
  readonly launch?: Register;
}

/** Constrains a TDX measurement register by register; `undefined` is unconstrained. */
export interface ExpectedTdx {
  readonly platform: "tdx";
  readonly mrtd?: Register;
  readonly rtmr0?: Register;
  readonly rtmr1?: Register;
  readonly rtmr2?: Register;
  readonly rtmr3?: Register;
}

/** A set of registers a measurement must match: a release's fixed registers or a caller's pins. */
export type Expected = ExpectedSevSnp | ExpectedTdx;

/** Lowercase hex encoding of a register. */
export function registerHex(r: Register): string {
  let s = "";
  for (const b of r) s += b.toString(16).padStart(2, "0");
  return s;
}
