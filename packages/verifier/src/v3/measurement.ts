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

const copy = (r: Register): Register => r.slice();
const copyOpt = (r: Register | undefined): Register | undefined => r?.slice();

/** A deep copy sharing no register buffers with the original. */
export function cloneMeasurement<M extends Measurement>(m: M): M {
  switch (m.platform) {
    case "sev-snp":
      return { platform: "sev-snp", launch: copy(m.launch) } as M;
    case "tdx":
      return {
        platform: "tdx",
        mrtd: copy(m.mrtd),
        rtmr0: copy(m.rtmr0),
        rtmr1: copy(m.rtmr1),
        rtmr2: copy(m.rtmr2),
        rtmr3: copy(m.rtmr3),
      } as M;
  }
}

/** A deep copy sharing no register buffers with the original; unset registers stay unset. */
export function cloneExpected<E extends Expected>(e: E): E {
  switch (e.platform) {
    case "sev-snp":
      return { platform: "sev-snp", launch: copyOpt(e.launch) } as E;
    case "tdx":
      return {
        platform: "tdx",
        mrtd: copyOpt(e.mrtd),
        rtmr0: copyOpt(e.rtmr0),
        rtmr1: copyOpt(e.rtmr1),
        rtmr2: copyOpt(e.rtmr2),
        rtmr3: copyOpt(e.rtmr3),
      } as E;
  }
}
