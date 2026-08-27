// Engine-neutral v3 stage runner shared by the Node CLI (cli.ts) and the
// browser conformance test. No node:/process/Buffer here — this module must
// execute unchanged in a browser (Go: verifier/conformance/conformance.go).

// The full-verify stage consumes the SDK's public surface (SDK_SURFACE_SPEC
// §1); block stages deliberately reach internal layers.
import {
  hpkePublicKey,
  tlsPublicKeyFP,
  VerificationError,
  verifyDocumentV3,
} from "@tinfoilsh/verifier";
import {
  check,
  CollateralSigstoreCodeV1Format,
  CollateralSigstorePlatformV1Format,
  decodeBase64,
  decodeHex,
  parseDocument,
  quoteAuthenticate,
  referenceValuesCollateral,
  type Document,
} from "../../verifier/dist/v3/index.js";
import {
  authenticateCode,
  authenticatePlatformEndorsements,
  type ProvenanceOpts,
} from "../../verifier/dist/v3/provenance/provenance.js";
import { pemDecode } from "../../verifier/dist/v3/der.js";
import { parseCertificate } from "../../verifier/dist/v3/tdx/der.js";
import {
  StageAssemblePolicy,
  StageAuthenticateProvenance,
  StageAuthenticateQuote,
  StageCheckEnvelope,
  StageVerify,
} from "./capabilities.js";

export const ExitAccepted = 0; // verification accepted; outputs populated
export const ExitInternal = 1; // unexpected adapter error
export const ExitRejected = 10; // verification rejected; rejection populated
export const ExitUnsupported = 20; // stage/capability not supported by this SDK
export const ExitMalformed = 30; // input did not parse

// Input is the fixture/stdin JSON: a v3 document, the verifier-supplied
// nonce, the pinned repo, and the synthetic roots it was produced under.
// Empty root fields select the embedded production roots.
export interface Input {
  schema_version?: string;
  document_b64?: string;
  nonce_hex?: string;
  repo?: string;
  amd_root_ca_pem?: string;
  ask_pem?: string;
  intel_sgx_root_pem?: string;
  sigstore_trusted_root_json_b64?: string;
  verification_time_unix?: number;
}

// Output is the wire JSON. Exactly one of outputs / rejection is set.
export interface Output {
  stage: string;
  accepted: boolean;
  outputs?: Record<string, unknown>;
  rejection?: { code: string };
}

export interface StageResult {
  output: Output;
  exitCode: number;
}

function reject(stage: string, code: string): StageResult {
  return { output: { stage, accepted: false, rejection: { code } }, exitCode: ExitRejected };
}

function malformed(stage: string): StageResult {
  return { output: { stage, accepted: false, rejection: { code: "MALFORMED_INPUT" } }, exitCode: ExitMalformed };
}

// runStage executes one stage and returns the wire Output plus the adapter
// exit code (Go: conformance.Run).
export async function runStage(stage: string, input: Input): Promise<StageResult> {
  if (input.schema_version !== "1") {
    return malformed(stage);
  }
  let doc: Uint8Array;
  let nonce: Uint8Array;
  try {
    doc = decodeBase64(input.document_b64 ?? "");
  } catch {
    return malformed(stage);
  }
  try {
    nonce = decodeHex(input.nonce_hex ?? "");
  } catch {
    return malformed(stage);
  }
  // Mirror Go Input.roots(): the AMD anchor is the ARK plus its ASK (KDS
  // convention) and must be supplied together; the Sigstore trusted root
  // must be decodable base64 JSON (Go: NewClientFromJSON at Run entry).
  const amd = input.amd_root_ca_pem ?? "";
  const ask = input.ask_pem ?? "";
  if ((amd !== "") !== (ask !== "")) {
    return malformed(stage);
  }
  // KDS cert_chain is ASK then ARK; empty selects the embedded root.
  const amdRootPEM = amd !== "" ? `${ask.trim()}\n${amd.trim()}\n` : undefined;
  const intelRootPEM = (input.intel_sgx_root_pem ?? "") !== "" ? input.intel_sgx_root_pem : undefined;
  const provOpts: ProvenanceOpts = {};
  if ((input.sigstore_trusted_root_json_b64 ?? "") !== "") {
    try {
      const trustRootJSON = decodeBase64(input.sigstore_trusted_root_json_b64 as string);
      JSON.parse(new TextDecoder().decode(trustRootJSON));
      provOpts.trustRootJSON = trustRootJSON;
    } catch {
      return malformed(stage);
    }
  }
  // verification_time_unix pins the validity-window and freshness-appraisal
  // clock so a frozen document replays at its capture time; 0 uses the
  // current time (Go: Run's Set/ResetVerificationTime).
  const verificationTime =
    (input.verification_time_unix ?? 0) !== 0 ? new Date((input.verification_time_unix as number) * 1000) : undefined;

  switch (stage) {
    case StageCheckEnvelope:
      try {
        await check(doc, nonce);
      } catch {
        return reject(stage, "ENVELOPE_REJECTED");
      }
      return { output: { stage, accepted: true }, exitCode: ExitAccepted };
    case StageAuthenticateProvenance: {
      let parsed: Document;
      try {
        parsed = parseDocument(doc);
      } catch {
        return malformed(stage);
      }
      try {
        const codeRef = referenceValuesCollateral(parsed, CollateralSigstoreCodeV1Format);
        const code = await authenticateCode(
          codeRef.sigstoreBundle,
          input.repo ?? "",
          codeRef.tag,
          codeRef.digest,
          provOpts,
        );
        return {
          output: {
            stage,
            accepted: true,
            outputs: {
              code_digest: code.digest,
              code_measurement: { type: code.measurement.type, registers: code.measurement.registers },
            },
          },
          exitCode: ExitAccepted,
        };
      } catch {
        return reject(stage, "PROVENANCE_REJECTED");
      }
    }
    case StageAssemblePolicy: {
      let parsed: Document;
      try {
        parsed = parseDocument(doc);
      } catch {
        return malformed(stage);
      }
      try {
        const platRef = referenceValuesCollateral(parsed, CollateralSigstorePlatformV1Format);
        await authenticatePlatformEndorsements(
          platRef.sigstoreBundle,
          platRef.repo,
          platRef.tag,
          platRef.digest,
          provOpts,
        );
        return { output: { stage, accepted: true }, exitCode: ExitAccepted };
      } catch {
        return reject(stage, "PROVENANCE_REJECTED");
      }
    }
    case StageAuthenticateQuote: {
      let parsed: Document;
      try {
        parsed = parseDocument(doc);
      } catch {
        return malformed(stage);
      }
      // Go parses an injected Intel root eagerly (tdx.SetIntelRoot); a PEM
      // that does not parse is malformed input, not a rejection.
      if (intelRootPEM !== undefined && !parsesAsCertificate(intelRootPEM)) {
        return malformed(stage);
      }
      try {
        const auth = await quoteAuthenticate(parsed, { amdRootPEM, intelRootPEM, now: verificationTime });
        return {
          output: {
            stage,
            accepted: true,
            outputs: {
              enclave_measurement: { type: auth.measurement.type, registers: auth.measurement.registers },
            },
          },
          exitCode: ExitAccepted,
        };
      } catch {
        return reject(stage, "QUOTE_REJECTED");
      }
    }
    case StageVerify: {
      if (intelRootPEM !== undefined && !parsesAsCertificate(intelRootPEM)) {
        return malformed(stage);
      }
      try {
        const verified = await verifyDocumentV3(doc, nonce, input.repo ?? "", {
          sigstoreRootJSON: provOpts.trustRootJSON,
          amdRootPEM,
          intelRootPEM,
          verificationTime,
        });
        // A document that verifies but endorses no usable channel keys is
        // useless to every real client, so the full stage requires both
        // (Go: verifyFull); the public accessors throw when a key is absent
        // or format-mismatched.
        let tlsFP: string;
        let hpke: string;
        try {
          tlsFP = tlsPublicKeyFP(verified);
          hpke = hpkePublicKey(verified);
        } catch {
          return reject(stage, "ENVELOPE_REJECTED");
        }
        const outputs: Record<string, unknown> = {
          code_digest: verified.codeDigest,
          code_measurement: { type: verified.codeMeasurement.type, registers: verified.codeMeasurement.registers },
          enclave_measurement: {
            type: verified.enclaveMeasurement.type,
            registers: verified.enclaveMeasurement.registers,
          },
          tls_public_key_fp: tlsFP,
          hpke_public_key: hpke,
        };
        return { output: { stage, accepted: true, outputs }, exitCode: ExitAccepted };
      } catch (err) {
        // The first failing step names the layer (Go: verifyFull).
        if (err instanceof VerificationError) {
          return reject(stage, err.layer);
        }
        throw err;
      }
    }
    default:
      return { output: { stage, accepted: false }, exitCode: ExitUnsupported };
  }
}

// parsesAsCertificate uses the same PEM/DER parser the TDX layer uses for an
// injected root (tdx/authenticate rootFromPEM), keeping the malformed-input
// gate engine-neutral (Node's X509Certificate is unavailable in browsers).
function parsesAsCertificate(pem: string): boolean {
  const block = pemDecode(pem);
  if (block === undefined) return false;
  try {
    parseCertificate(block.der);
    return true;
  } catch {
    return false;
  }
}
