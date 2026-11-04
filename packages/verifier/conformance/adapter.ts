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
 * mutates no production state.
 */
import * as document from "../src/v3/document/document.js";
import { UsageError, VerificationError } from "../src/v3/errors.js";
import { MULTI_PLATFORM_PREDICATE_TYPE, ProvenanceClient } from "../src/v3/internal/endorsement/provenance.js";
import { parseReference } from "../src/v3/internal/endorsement/reference.js";
import { ARTIFACT_FORMAT } from "../src/v3/internal/policy/artifact.js";
import * as quote from "../src/v3/internal/quote/quote.js";
import { registerHex, type Expected, type Measurement as V3Measurement, type Register } from "../src/v3/measurement.js";
import { dangerousTestOnlyVerifier, type DangerousTestOnlyRoots } from "../src/v3/verifier.js";
import { checkTime, newTimePolicy } from "../src/v3/internal/endorsement/time.js";
import { parseBundleBytes } from "../src/v3/internal/sigstore/bundle.js";
import { pinnedKeys, verifyKeyedBundle } from "../src/v3/internal/sigstore/keyed.js";
import { verifyTimestamp } from "../src/v3/internal/sigstore/timestamp.js";
import { embeddedTrustedRoot, parseTrustedRoot, type TrustedRoot } from "../src/v3/internal/sigstore/trusted-root.js";

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
  AuthenticateApproval: "v3-authenticate-approval",
  VerifyTimestamp: "v3-verify-timestamp",
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
  bundle_json_b64?: string;
  signing_keys_pem?: string[];
  artifact_digest_hex?: string;
  timestamp_response_b64?: string;
  timestamp_input_b64?: string;
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
  signing_key_hint?: string;
  timestamp?: string;
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
 * Never throws: unexpected errors map to {@link ExitCode.Internal}; a stage
 * this adapter does not know maps to {@link ExitCode.Unsupported}.
 */
export async function run(stage: string, raw: unknown): Promise<Result> {
  try {
    return await runStage(stage, raw);
  } catch {
    return { output: { stage, accepted: false }, exitCode: ExitCode.Internal };
  }
}

async function runStage(stage: string, raw: unknown): Promise<Result> {
  const in_ = decodeInput(raw);
  if (in_ === undefined) return malformed(stage);

  // Pin the validity-window and freshness clock for a frozen document.
  const appraisal = in_.verification_time_unix ? new Date(in_.verification_time_unix * 1000) : new Date();

  if (in_.schema_version !== SCHEMA_VERSION) return malformed(stage);
  const roots = rootsOf(in_);
  if (roots === undefined) return malformed(stage);

  // The approval and timestamp stages take no document.
  if (stage === Stage.AuthenticateApproval) return authenticateApproval(in_, roots);
  if (stage === Stage.VerifyTimestamp) return verifyTimestampStage(in_, roots, appraisal);

  const doc = decodeBase64Std(in_.document_b64);
  if (doc === undefined) return malformed(stage);
  const nonce = decodeHex(in_.nonce_hex);
  if (nonce === undefined) return malformed(stage);

  // An injected Sigstore root that is not a trusted root is malformed input
  // on every document stage, so the provenance client is built before
  // dispatch.
  let prov: ProvenanceClient;
  try {
    prov = roots.sigstore ? await ProvenanceClient.fromJSON(roots.sigstore) : await ProvenanceClient.default();
  } catch (err) {
    return malformed(stage);
  }

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
      return layer(stage, "PROVENANCE_REJECTED", async () => {
        const codeRef = parsed.sigstoreCode();
        const pin = parseReference(in_.repo);
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

/**
 * The injected Sigstore root, or the embedded one; undefined when the
 * injected document is not a trusted root, which the block stages report as
 * malformed input rather than as a verification failure.
 */
async function sigstoreRoot(roots: DangerousTestOnlyRoots): Promise<TrustedRoot | undefined> {
  if (!roots.sigstore) return embeddedTrustedRoot();
  try {
    return await parseTrustedRoot(roots.sigstore);
  } catch (err) {
    return undefined;
  }
}

/**
 * Verifies a key-signed approval bundle under the pinned keys and checks that
 * the statement carries the artifact digest; yields the hint of the key that
 * verified. Undecodable inputs, unparseable or repeated keys and an
 * unparseable trust root are malformed.
 */
async function authenticateApproval(in_: Input, roots: DangerousTestOnlyRoots): Promise<Result> {
  const stage = Stage.AuthenticateApproval;
  const bundleBytes = decodeBase64Std(in_.bundle_json_b64 ?? "");
  const digest = decodeHex(in_.artifact_digest_hex ?? "");
  const pems = in_.signing_keys_pem ?? [];
  if (bundleBytes === undefined || digest === undefined || pems.length === 0) return malformed(stage);
  let keys;
  try {
    keys = await pinnedKeys(pems);
  } catch (err) {
    return malformed(stage);
  }
  const root = await sigstoreRoot(roots);
  if (root === undefined) return malformed(stage);
  return layer(stage, "PROVENANCE_REJECTED", async () => {
    const bundle = parseBundleBytes(bundleBytes);
    const hint = await verifyKeyedBundle(root, bundle, keys, digest);
    return accept(stage, { signing_key_hint: hint });
  });
}

/**
 * Verifies an RFC 3161 response over the given bytes against the trusted
 * root's timestamp authorities, and requires the stated time to lie within
 * the default window around the appraisal clock. The clock is required, and
 * an unparseable trust root is malformed.
 */
async function verifyTimestampStage(in_: Input, roots: DangerousTestOnlyRoots, appraisal: Date): Promise<Result> {
  const stage = Stage.VerifyTimestamp;
  const response = decodeBase64Std(in_.timestamp_response_b64 ?? "");
  const input = decodeBase64Std(in_.timestamp_input_b64 ?? "");
  if (response === undefined || input === undefined || !in_.verification_time_unix) return malformed(stage);
  const root = await sigstoreRoot(roots);
  if (root === undefined) return malformed(stage);
  return layer(stage, "PROVENANCE_REJECTED", async () => {
    const at = await verifyTimestamp(root, response, input);
    checkTime(newTimePolicy(appraisal, 0, 0), at);
    return accept(stage, { timestamp: at.toISOString().replace(/\.\d{3}Z$/, "Z") });
  });
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
    code_digest: verified.codeDigest(),
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
    return reject(stage, code);
  }
}

async function decodeOrUndefined(doc: Uint8Array): Promise<document.Document | undefined> {
  try {
    return await document.dangerousTestOnlyDecode(doc);
  } catch (err) {
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

// --- input decoding ---

const STRING_FIELDS = [
  "schema_version",
  "document_b64",
  "nonce_hex",
  "repo",
  "amd_root_ca_pem",
  "ask_pem",
  "intel_sgx_root_pem",
  "sigstore_trusted_root_json_b64",
  "bundle_json_b64",
  "artifact_digest_hex",
  "timestamp_response_b64",
  "timestamp_input_b64",
] as const;

/**
 * Validates the parsed stdin value against the Input shape: unknown members
 * are ignored, absent or null members take their zero value ("" or 0), and a
 * member of the wrong type is malformed.
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
  const keys = obj.signing_keys_pem;
  if (keys === undefined || keys === null) {
    out.signing_keys_pem = [];
  } else if (Array.isArray(keys) && keys.every((k) => typeof k === "string")) {
    out.signing_keys_pem = keys;
  } else {
    return undefined;
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

/** Standard base64: the +/ alphabet, padded to a multiple of 4; CR and LF are ignored. */
export function decodeBase64Std(s: string): Uint8Array | undefined {
  const clean = s.replace(/[\r\n]/g, "");
  if (clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(clean)) {
    return undefined;
  }
  return new Uint8Array(Buffer.from(clean, "base64"));
}

/** Hex of even length, either case. */
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
