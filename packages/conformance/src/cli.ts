#!/usr/bin/env node
// tinfoil-js v3 conformance adapter (Go: cmd/tinfoil-conformance +
// verifier/conformance/conformance.go).
//
//   node cli.js <stage>        Input JSON on stdin -> Output JSON on stdout,
//                              exit code = verdict
//   node cli.js capabilities   self-description JSON on stdout, exit 0
//
// Exit codes are the cross-SDK adapter contract: the suite reads them to
// decide pass/skip and never depends on stdout for the verdict.

import {
  check,
  CollateralSigstoreCodeV1Format,
  CollateralSigstorePlatformV1Format,
  decodeBase64,
  decodeHex,
  parseDocument,
  referenceValuesCollateral,
  type Document,
} from "../../verifier/dist/v3/index.js";
import {
  authenticateCode,
  authenticatePlatformEndorsements,
  type ProvenanceOpts,
} from "../../verifier/dist/v3/provenance/provenance.js";
import {
  capabilities,
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

// Input is the stdin JSON: a v3 document, the verifier-supplied nonce, the
// pinned repo, and the synthetic roots it was produced under. Empty root
// fields select the embedded production roots.
interface Input {
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

// Output is the stdout JSON. Exactly one of outputs / rejection is set.
interface Output {
  stage: string;
  accepted: boolean;
  outputs?: Record<string, unknown>;
  rejection?: { code: string };
}

function reject(stage: string, code: string): [Output, number] {
  return [{ stage, accepted: false, rejection: { code } }, ExitRejected];
}

function malformed(stage: string): [Output, number] {
  return [{ stage, accepted: false, rejection: { code: "MALFORMED_INPUT" } }, ExitMalformed];
}

// run executes one stage and returns the wire Output plus the adapter exit
// code (Go: conformance.Run).
async function run(stage: string, input: Input): Promise<[Output, number]> {
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
  const provOpts: ProvenanceOpts = {};
  if ((input.sigstore_trusted_root_json_b64 ?? "") !== "") {
    try {
      const trustRootJSON = decodeBase64(input.sigstore_trusted_root_json_b64 as string);
      JSON.parse(Buffer.from(trustRootJSON).toString("utf-8"));
      provOpts.trustRootJSON = trustRootJSON;
    } catch {
      return malformed(stage);
    }
  }

  switch (stage) {
    case StageCheckEnvelope:
      try {
        check(doc, nonce);
      } catch {
        return reject(stage, "ENVELOPE_REJECTED");
      }
      return [{ stage, accepted: true }, ExitAccepted];
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
        return [
          {
            stage,
            accepted: true,
            outputs: {
              code_digest: code.digest,
              code_measurement: { type: code.measurement.type, registers: code.measurement.registers },
            },
          },
          ExitAccepted,
        ];
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
        return [{ stage, accepted: true }, ExitAccepted];
      } catch {
        return reject(stage, "PROVENANCE_REJECTED");
      }
    }
    case StageVerify:
    case StageAuthenticateQuote:
      // TODO(integration agent): wire these stages once the quote (sev/tdx)
      // and policy-assembly layers land; until then they are honestly
      // unsupported so the suite skips their fixtures.
      return [{ stage, accepted: false }, ExitUnsupported];
    default:
      return [{ stage, accepted: false }, ExitUnsupported];
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks).toString("utf-8");
}

function writeJSON(v: unknown): void {
  process.stdout.write(JSON.stringify(v, null, 2) + "\n");
}

async function main(): Promise<number> {
  const cmd = process.argv[2];
  if (cmd === undefined || cmd === "") {
    process.stderr.write("usage: tinfoil-conformance <stage>|capabilities\n");
    return ExitInternal;
  }

  if (cmd === "capabilities") {
    writeJSON(capabilities());
    return ExitAccepted;
  }

  let input: Input;
  try {
    input = JSON.parse(await readStdin()) as Input;
  } catch {
    writeJSON({ stage: cmd, accepted: false, rejection: { code: "MALFORMED_INPUT" } });
    return ExitMalformed;
  }

  const [out, code] = await run(cmd, input);
  writeJSON(out);
  return code;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`internal error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    process.exitCode = ExitInternal;
  },
);
