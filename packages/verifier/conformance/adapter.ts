/**
 * The tinfoil-js v3 conformance adapter: runs shared cross-SDK fixtures
 * against the verifier and reports results in the language-neutral wire
 * contract (tinfoil-conformance docs/CONFORMANCE_ADAPTER_SPEC.md).
 *
 * The full-verify stage is one `Verifier.verifyV3At` call, so fixtures
 * appraise exactly the code production runs; the layer on its
 * VerificationError names the rejection. The block stages isolate one layer
 * by calling the internal document, endorsement and quote modules directly.
 *
 * Test roots and the appraisal clock are per-call arguments; the adapter
 * mutates no production state. Mirrors tinfoil-go verify/conformance.
 */
import * as document from "../src/v3/document/document.js";
import { NotImplementedError, UsageError, VerificationError } from "../src/v3/errors.js";
import * as endorsement from "../src/v3/internal/endorsement/provenance.js";
import { MULTI_PLATFORM_PREDICATE_TYPE } from "../src/v3/internal/endorsement/provenance.js";
import { ARTIFACT_FORMAT } from "../src/v3/internal/policy/artifact.js";
import * as quote from "../src/v3/internal/quote/quote.js";
import { registerHex, type Expected, type Measurement as V3Measurement, type Register } from "../src/v3/measurement.js";
import { dangerousTestOnlyVerifier, type DangerousTestOnlyRoots } from "../src/v3/verifier.js";

export const SCHEMA_VERSION = "1";
export const SDK_NAME = "tinfoil-js";

/** Exit codes are the verdict; the suite never reads stdout for it. */
export const ExitCode = {
  Accepted: 0,
  Internal: 1,
  Rejected: 10,
  Unsupported: 20,
  Malformed: 30,
} as const;
export type ExitCode = (typeof ExitCode)[keyof typeof ExitCode];

export const Stage = {
  Verify: "verify-attestation-v3",
  CheckEnvelope: "v3-check-envelope",
  AuthenticateProvenance: "v3-authenticate-provenance",
  AssemblePolicy: "v3-assemble-policy",
  AuthenticateQuote: "v3-authenticate-quote",
} as const;

export type RejectionCode =
  | "ENVELOPE_REJECTED"
  | "PROVENANCE_REJECTED"
  | "QUOTE_REJECTED"
  | "POLICY_REJECTED"
  | "MALFORMED_INPUT";

/** The stdin JSON (schemas/v3/input.schema.json). */
export interface Input {
  schema_version: string;
  document_b64: string;
  nonce_hex: string;
  repo: string;
  amd_root_ca_pem?: string;
  ask_pem?: string;
  intel_sgx_root_pem?: string;
  sigstore_trusted_root_json_b64?: string;
  verification_time_unix?: number;
}

export interface Measurement {
  type: string;
  registers: string[];
}

export interface AcceptOutputs {
  code_digest?: string;
  code_measurement?: Measurement;
  enclave_measurement?: Measurement;
  tls_public_key_fp?: string;
  hpke_public_key?: string;
  channel_binding?: string;
}

/** The stdout JSON (schemas/v3/output.schema.json). */
export interface Output {
  stage: string;
  accepted: boolean;
  outputs?: AcceptOutputs;
  rejection?: { code: RejectionCode };
}

export interface Result {
  output: Output;
  exitCode: ExitCode;
}

export function capabilities(): Record<string, unknown> {
  return {
    schema_version: SCHEMA_VERSION,
    sdk: SDK_NAME,
    v3: {
      supported: true,
      stages_supported: Object.values(Stage),
      synthetic_roots: { amd: true, intel: true, sigstore: true },
      freshness_enforced: true,
      // TODO(v3): live-verify lane.
      live_verify: false,
      channel_binding: "tls-spki",
    },
  };
}

/**
 * Executes one stage and returns the wire output plus the exit code.
 * Never throws: unexpected errors map to {@link ExitCode.Internal}, and
 * placeholders still awaiting the v3 port map to {@link ExitCode.Unsupported}.
 */
export async function run(stage: string, raw: unknown): Promise<Result> {
  try {
    return await runStage(stage, raw);
  } catch (err) {
    if (err instanceof NotImplementedError) {
      return { output: { stage, accepted: false }, exitCode: ExitCode.Unsupported };
    }
    return { output: { stage, accepted: false }, exitCode: ExitCode.Internal };
  }
}

async function runStage(stage: string, raw: unknown): Promise<Result> {
  const in_ = decodeInput(raw);
  if (in_ === undefined) return malformed(stage);

  // Pin the validity-window and freshness clock for a frozen document.
  const appraisal = in_.verification_time_unix ? new Date(in_.verification_time_unix * 1000) : new Date();

  if (in_.schema_version !== SCHEMA_VERSION) return malformed(stage);
  const doc = decodeBase64Std(in_.document_b64);
  if (doc === undefined) return malformed(stage);
  const nonce = decodeHex(in_.nonce_hex);
  if (nonce === undefined) return malformed(stage);
  const roots = rootsOf(in_);
  if (roots === undefined) return malformed(stage);

  // TODO(v3): tinfoil-go builds the provenance client before dispatch, so a
  // bad sigstore root is MALFORMED_INPUT on every stage. It's lazy here until
  // ProvenanceClient is implemented, so the envelope stage isn't blocked on it.
  const provClient = async () => {
    try {
      return roots.sigstore ? await endorsement.ProvenanceClient.fromJSON(roots.sigstore) : await endorsement.ProvenanceClient.default();
    } catch (err) {
      if (err instanceof NotImplementedError) throw err;
      return undefined;
    }
  };

  switch (stage) {
    case Stage.Verify:
      return verifyFull(doc, nonce, in_.repo, roots, appraisal);

    case Stage.CheckEnvelope:
      return layer(stage, "ENVELOPE_REJECTED", async () => {
        await document.parse(doc, nonce);
        return accept(stage);
      });

    case Stage.AuthenticateProvenance: {
      const parsed = await decodeOrUndefined(doc);
      if (parsed === undefined) return malformed(stage);
      const prov = await provClient();
      if (prov === undefined) return malformed(stage);
      return layer(stage, "PROVENANCE_REJECTED", async () => {
        const codeRef = parsed.sigstoreCode();
        const pin = endorsement.parseReference(in_.repo);
        const code = await prov.authenticateCode(codeRef.bundle, pin, codeRef.tag, codeRef.digest);
        return accept(stage, {
          code_digest: code.digest,
          // The release's own predicate: SNP launch, then TDX RTMR1 and RTMR2.
          code_measurement: {
            type: MULTI_PLATFORM_PREDICATE_TYPE,
            registers: [hexOrEmpty(code.sevSnp.launch), hexOrEmpty(code.tdx.rtmr1), hexOrEmpty(code.tdx.rtmr2)],
          },
        });
      });
    }

    case Stage.AssemblePolicy: {
      const parsed = await decodeOrUndefined(doc);
      if (parsed === undefined) return malformed(stage);
      const prov = await provClient();
      if (prov === undefined) return malformed(stage);
      return layer(stage, "PROVENANCE_REJECTED", async () => {
        const ref = parsed.sigstorePlatform();
        await prov.authenticatePlatformEndorsements(ref.bundle, ref.repo, ref.tag, ref.digest, ARTIFACT_FORMAT);
        return accept(stage);
      });
    }

    case Stage.AuthenticateQuote: {
      const parsed = await decodeOrUndefined(doc);
      if (parsed === undefined) return malformed(stage);
      return layer(stage, "QUOTE_REJECTED", async () => {
        const auth = await quote.authenticate(parsed.cpuEvidence(), parsed.cpuEndorsements(), appraisal, {
          dangerousTestOnlyRoots: roots,
        });
        return accept(stage, { enclave_measurement: measurementOf(auth.measurement) });
      });
    }

    default:
      return { output: { stage, accepted: false }, exitCode: ExitCode.Unsupported };
  }
}

/** Runs the whole flow through the verifier; the error's layer names the rejection. */
async function verifyFull(
  doc: Uint8Array,
  nonce: Uint8Array,
  repo: string,
  roots: DangerousTestOnlyRoots,
  appraisal: Date,
): Promise<Result> {
  const stage = Stage.Verify;
  let verified;
  try {
    const verifier = await dangerousTestOnlyVerifier(roots);
    verified = await verifier.verifyV3At(doc, nonce, repo, appraisal);
  } catch (err) {
    if (err instanceof NotImplementedError) throw err;
    const mapped = rejectionCode(err);
    if (mapped === undefined) return { output: { stage, accepted: false }, exitCode: ExitCode.Internal };
    return { output: { stage, accepted: false, rejection: { code: mapped.code } }, exitCode: mapped.exitCode };
  }
  // A document that verifies but endorses no usable channel keys is useless
  // to every real client, so the full stage requires both.
  const tlsFP = verified.tlsPublicKeyFP();
  const hpke = verified.hpkePublicKey();
  if (tlsFP === undefined || hpke === undefined) {
    return reject(stage, "ENVELOPE_REJECTED");
  }
  return accept(stage, {
    code_digest: verified.codeDigest,
    code_measurement: expectedOf(verified.codeMeasurement()),
    enclave_measurement: measurementOf(verified.enclaveMeasurement()),
    tls_public_key_fp: tlsFP,
    hpke_public_key: hpke,
  });
}

/** Maps a verifier error to its wire code, or undefined if it is not a classified error. */
export function rejectionCode(err: unknown): { code: RejectionCode; exitCode: ExitCode } | undefined {
  if (err instanceof UsageError) return { code: "MALFORMED_INPUT", exitCode: ExitCode.Malformed };
  if (err instanceof VerificationError) {
    switch (err.layer) {
      case "envelope":
        return { code: "ENVELOPE_REJECTED", exitCode: ExitCode.Rejected };
      case "provenance":
        return { code: "PROVENANCE_REJECTED", exitCode: ExitCode.Rejected };
      case "quote":
        return { code: "QUOTE_REJECTED", exitCode: ExitCode.Rejected };
      case "policy":
        return { code: "POLICY_REJECTED", exitCode: ExitCode.Rejected };
    }
  }
  return undefined;
}

/** Runs a block-stage body, attributing any failure to `code`. */
async function layer(stage: string, code: RejectionCode, body: () => Promise<Result>): Promise<Result> {
  try {
    return await body();
  } catch (err) {
    if (err instanceof NotImplementedError) throw err;
    return reject(stage, code);
  }
}

async function decodeOrUndefined(doc: Uint8Array): Promise<document.Document | undefined> {
  try {
    return await document.dangerousTestOnlyDecode(doc);
  } catch (err) {
    if (err instanceof NotImplementedError) throw err;
    return undefined;
  }
}

const SEV_SNP_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const TDX_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/tdx-guest/v2";

/** Lays out a measurement's registers in the wire's platform register order. */
export function measurementOf(m: V3Measurement): Measurement {
  switch (m.platform) {
    case "sev-snp":
      return { type: SEV_SNP_MEASUREMENT_TYPE, registers: [registerHex(m.launch)] };
    case "tdx":
      return { type: TDX_MEASUREMENT_TYPE, registers: [m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2, m.rtmr3].map(registerHex) };
  }
}

/** Like {@link measurementOf}, with "" for an unconstrained register. */
export function expectedOf(e: Expected): Measurement {
  switch (e.platform) {
    case "sev-snp":
      return { type: SEV_SNP_MEASUREMENT_TYPE, registers: [hexOrEmpty(e.launch)] };
    case "tdx":
      return { type: TDX_MEASUREMENT_TYPE, registers: [e.mrtd, e.rtmr0, e.rtmr1, e.rtmr2, e.rtmr3].map(hexOrEmpty) };
  }
}

function hexOrEmpty(r: Register | undefined): string {
  return r === undefined ? "" : registerHex(r);
}

function accept(stage: string, outputs?: AcceptOutputs): Result {
  return { output: { stage, accepted: true, ...(outputs && { outputs }) }, exitCode: ExitCode.Accepted };
}

function reject(stage: string, code: RejectionCode): Result {
  return { output: { stage, accepted: false, rejection: { code } }, exitCode: ExitCode.Rejected };
}

function malformed(stage: string): Result {
  return { output: { stage, accepted: false, rejection: { code: "MALFORMED_INPUT" } }, exitCode: ExitCode.Malformed };
}

// --- input decoding (matches Go encoding/json + encoding/base64 + encoding/hex) ---

const STRING_FIELDS = [
  "schema_version",
  "document_b64",
  "nonce_hex",
  "repo",
  "amd_root_ca_pem",
  "ask_pem",
  "intel_sgx_root_pem",
  "sigstore_trusted_root_json_b64",
] as const;

/**
 * Validates the parsed stdin value against the Input shape. Like Go's
 * json.Unmarshal into a struct: unknown members are ignored, absent members
 * take their zero value, and a member of the wrong type is malformed.
 */
function decodeInput(raw: unknown): Input | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  const obj = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of STRING_FIELDS) {
    const v = obj[k];
    if (v === undefined || v === null) {
      out[k] = "";
    } else if (typeof v === "string") {
      out[k] = v;
    } else {
      return undefined;
    }
  }
  const t = obj.verification_time_unix;
  if (t === undefined || t === null) {
    out.verification_time_unix = 0;
  } else if (typeof t === "number" && Number.isSafeInteger(t)) {
    out.verification_time_unix = t;
  } else {
    return undefined;
  }
  return out as unknown as Input;
}

/** Go base64.StdEncoding: padded standard alphabet; CR and LF are ignored. */
export function decodeBase64Std(s: string): Uint8Array | undefined {
  const clean = s.replace(/[\r\n]/g, "");
  if (clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(clean)) {
    return undefined;
  }
  return new Uint8Array(Buffer.from(clean, "base64"));
}

/** Go hex.DecodeString: even length, either case. */
export function decodeHex(s: string): Uint8Array | undefined {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return undefined;
  return new Uint8Array(Buffer.from(s, "hex"));
}

/** The injected anchors; an absent field selects the embedded production root. */
function rootsOf(in_: Input): DangerousTestOnlyRoots | undefined {
  const enc = new TextEncoder();
  const roots: { amd?: Uint8Array; intel?: Uint8Array; sigstore?: Uint8Array } = {};
  const ark = in_.amd_root_ca_pem ?? "";
  const ask = in_.ask_pem ?? "";
  if (ark !== "" && ask !== "") {
    // KDS cert_chain order: ASK then ARK.
    roots.amd = enc.encode(`${ask.trim()}\n${ark.trim()}\n`);
  } else if (ark !== "" || ask !== "") {
    return undefined;
  }
  if (in_.intel_sgx_root_pem) roots.intel = enc.encode(in_.intel_sgx_root_pem);
  if (in_.sigstore_trusted_root_json_b64) {
    const j = decodeBase64Std(in_.sigstore_trusted_root_json_b64);
    if (j === undefined) return undefined;
    roots.sigstore = j;
  }
  return roots;
}
