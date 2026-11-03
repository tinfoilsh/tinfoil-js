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

const TDX_LABELS = ["MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"] as const;

/** Decodes a register from hex in either case. Throws on bad hex or length. */
export function parseRegister(s: string): Register {
  if (s.length !== 2 * REGISTER_SIZE) {
    throw new Error(`register must be ${2 * REGISTER_SIZE} hex characters, got ${s.length}`);
  }
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error("register is not hex");
  const r = new Uint8Array(REGISTER_SIZE);
  for (let i = 0; i < REGISTER_SIZE; i++) r[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return r;
}

/** One register, or undefined for "". */
function parseExpectedRegister(label: string, value: string): Register | undefined {
  if (value === "") return undefined;
  try {
    return parseRegister(value);
  } catch (err) {
    throw new Error(`${label}: ${(err as Error).message}`);
  }
}

/** Parses an SEV-SNP expectation; "" leaves the launch register unconstrained. */
export function parseExpectedSevSnp(launch: string): ExpectedSevSnp {
  return { platform: "sev-snp", launch: parseExpectedRegister("Launch", launch) };
}

/** Parses a TDX expectation; "" leaves that register unconstrained. */
export function parseExpectedTdx(mrtd: string, rtmr0: string, rtmr1: string, rtmr2: string, rtmr3: string): ExpectedTdx {
  const [m, r0, r1, r2, r3] = [mrtd, rtmr0, rtmr1, rtmr2, rtmr3].map((v, i) => parseExpectedRegister(TDX_LABELS[i], v));
  return { platform: "tdx", mrtd: m, rtmr0: r0, rtmr1: r1, rtmr2: r2, rtmr3: r3 };
}

/** Expectations that pin every register of `m`. */
export function expectedOf(m: Measurement): Expected {
  return cloneMeasurement(m);
}

/** Human-readable form: the platform name, then one labeled register per line, "any" if unset. */
export function formatMeasurement(m: Measurement | Expected): string {
  const [platform, labels, registers]: [string, readonly string[], (Register | undefined)[]] =
    m.platform === "sev-snp"
      ? ["SEV-SNP", ["Launch"], [m.launch]]
      : ["TDX", TDX_LABELS, [m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2, m.rtmr3]];
  let out = platform;
  registers.forEach((r, i) => {
    out += `\n${labels[i].padEnd(6)} ${r === undefined ? "any" : registerHex(r)}`;
  });
  return out;
}
